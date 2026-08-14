package supervisor

import (
	"context"
	"fmt"
	"log/slog"

	"bodsch.me/mailcow-watchdog/internal/check"
	"bodsch.me/mailcow-watchdog/internal/health"
	"bodsch.me/mailcow-watchdog/internal/metrics"
	"bodsch.me/mailcow-watchdog/internal/probe"
	"bodsch.me/mailcow-watchdog/internal/store"
)

// Event is raised when a check has spent its entire error budget.
//
// It carries what the supervisor needs to act, so that — unlike the shell, which
// pushed a bare service name through a FIFO and then had to fish the details
// back out of /tmp and Redis — nothing has to be looked up again.
type Event struct {
	// Check is the check that raised it.
	Check *check.Check
	// Snapshot is the health at the moment the budget ran out.
	Snapshot health.Snapshot
}

// Runner drives one check's loop: probe, account, sleep, repeat.
//
// In the shell this was a subshell per check plus a `while true` wrapper that
// re-entered the function after every threshold breach. The reset after an event
// is that re-entry.
type Runner struct {
	check   *check.Check
	tracker *health.Tracker
	gate    *Gate
	clock   Clock
	store   store.Store
	metrics *metrics.Metrics
	events  chan<- Event
	log     *slog.Logger
}

// NewRunner builds a runner for one check.
func NewRunner(c *check.Check, deps RunnerDeps) *Runner {
	return &Runner{
		check:   c,
		tracker: health.New(c.Service, c.Threshold),
		gate:    deps.Gate,
		clock:   deps.Clock,
		store:   deps.Store,
		metrics: deps.Metrics,
		events:  deps.Events,
		log:     deps.Log.With("check", c.Name),
	}
}

// RunnerDeps are the collaborators every runner shares.
type RunnerDeps struct {
	Gate    *Gate
	Clock   Clock
	Store   store.Store
	Metrics *metrics.Metrics
	Events  chan<- Event
	Log     *slog.Logger
}

// Name returns the check's identifier.
func (r *Runner) Name() string { return r.check.Name }

// Heal repays error points after the supervisor has acted on the service, so a
// recovering container is not restarted again on the next round.
func (r *Runner) Heal(points int) {
	before := r.tracker.Snapshot()
	after := r.tracker.Heal(points)
	if after.Remaining != before.Remaining {
		r.log.Debug("repaid error points after a restart",
			"points", points, "health", after.Remaining, "of", after.Threshold)
	}
}

// Snapshot returns the check's current health.
func (r *Runner) Snapshot() health.Snapshot { return r.tracker.Snapshot() }

// Run loops until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) {
	r.log.Info("check started",
		"threshold", r.check.Threshold, "probes", len(r.check.Probes))

	for {
		if err := r.gate.Wait(ctx); err != nil {
			r.log.Info("check stopped")
			return
		}

		snapshot := r.round(ctx)
		if ctx.Err() != nil {
			r.log.Info("check stopped")
			return
		}

		// The shell slept before leaving its loop, so the pause happens between
		// the last probe and the event, not after it.
		delay := r.check.Interval.Pick()
		if snapshot.Dead() {
			delay = r.check.DeadDelay
		}
		if err := r.clock.Sleep(ctx, delay); err != nil {
			r.log.Info("check stopped")
			return
		}

		if !snapshot.Dead() {
			continue
		}

		// Returning from the check function gave the shell a fresh err_count on
		// re-entry; the reset is that, made explicit.
		r.tracker.Reset()
		r.metrics.ObserveExhausted(r.check.Name)
		r.log.Warn("check hit its error limit", "event", r.check.Event)

		select {
		case r.events <- Event{Check: r.check, Snapshot: snapshot}:
		case <-ctx.Done():
			r.log.Info("check stopped")
			return
		}
	}
}

// round runs every probe once and folds the results into the error budget.
func (r *Runner) round(ctx context.Context) health.Snapshot {
	weight := 0

	for _, p := range r.check.Probes {
		res := probe.Run(ctx, p)
		weight += res.Weight()

		r.check.Record(fmt.Sprintf("%s: %s", res.Status, res.Message))
		r.metrics.ObserveProbe(r.check.Name, res.Probe, res.Status, res.Duration.Seconds())

		if res.Status == health.StatusOK {
			r.log.Debug("probe passed",
				"probe", res.Probe, "took", res.Duration, "detail", res.Message)
			continue
		}
		r.log.Warn("probe failed",
			"probe", res.Probe, "status", res.Status.String(), "points", res.Weight(),
			"took", res.Duration, "detail", res.Message)
	}

	snapshot := r.tracker.Record(weight)
	r.publish(ctx, snapshot)
	return snapshot
}

// publish mirrors the shell's progress(): a health record for the mailcow UI, a
// gauge for Prometheus and a line in the log.
func (r *Runner) publish(ctx context.Context, s health.Snapshot) {
	r.metrics.ObserveHealth(r.check.Name, s)

	if err := r.store.LogProgress(ctx, s); err != nil && ctx.Err() == nil {
		// Redis being unavailable is worth knowing about, but it must not stop
		// the check: the restart logic does not depend on it.
		r.log.Warn("cannot write the health record", "err", err)
	}

	level := r.log.Debug
	if s.Remaining < s.Threshold {
		level = r.log.Info
	}
	level("health level",
		"percent", s.Percent, "health", s.Remaining, "of", s.Threshold, "trend", s.Trend)
}
