// Package check composes probes into the monitored services.
//
// A check owns an error budget, a set of probes and the cadence at which they
// run. It corresponds to one *_checks function in watchdog.sh, and its Interval,
// DeadDelay and Service values are taken straight from there — the sleeps were
// tuned per service and the display names are what the mailcow UI shows.
package check

import (
	"context"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"bodsch.me/mailcow-watchdog/internal/probe"
)

// transcriptLines is how much probe output a check keeps for the notification
// body. watchdog.sh capped its /tmp/<service> files with `tail -50`.
const transcriptLines = 50

// Interval is a randomised sleep window.
//
// The shell staggered its loops with `sleep $(( ( RANDOM % 60 ) + 20 ))` so that
// nineteen checks starting at the same moment do not keep hitting the stack in
// lockstep. Both bounds are inclusive.
type Interval struct {
	Min time.Duration
	Max time.Duration
}

// Pick returns a duration from the window.
func (i Interval) Pick() time.Duration {
	if i.Max <= i.Min {
		return i.Min
	}
	// G404: the jitter only staggers the checks against each other, exactly as
	// bash's $RANDOM did. Nothing here is a secret or a token.
	return i.Min + rand.N(i.Max-i.Min+1) //nolint:gosec
}

// Fixed returns an interval with no jitter.
func Fixed(d time.Duration) Interval { return Interval{Min: d, Max: d} }

// Check is one monitored service.
type Check struct {
	// Name identifies the check in logs and metrics, e.g. "nginx".
	Name string
	// Service is the display name written to WATCHDOG_LOG, e.g. "Nginx". The
	// mailcow UI renders it verbatim.
	Service string
	// Event is what the supervisor acts on when the budget is exhausted, e.g.
	// "nginx-mailcow". Names ending in -mailcow identify a container to restart;
	// the others are notify-only.
	Event string
	// Threshold is the error budget in points.
	Threshold int
	// Probes run once per round; their weights are summed into the budget.
	Probes []probe.Probe
	// Interval is the pause between rounds while the service is healthy.
	Interval Interval
	// DeadDelay is the pause after the budget is exhausted, before the event is
	// raised. The shell used one second for most checks and a minute for the
	// ones whose events are only notifications.
	DeadDelay time.Duration

	// Bans, when set, returns the addresses banned during the most recent round.
	// Only the fail2ban check has one; its event notifies per address rather
	// than once for the whole round.
	Bans func() []string

	// details, when set, supplies the notification body instead of the probe
	// transcript.
	details func(ctx context.Context) string

	mu         sync.Mutex
	transcript []string
}

// Record appends probe output to the check's transcript.
func (c *Check) Record(lines ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, line := range lines {
		if line == "" {
			continue
		}
		c.transcript = append(c.transcript, line)
	}
	if extra := len(c.transcript) - transcriptLines; extra > 0 {
		c.transcript = append([]string(nil), c.transcript[extra:]...)
	}
}

// Details returns the body for a notification about this check.
func (c *Check) Details(ctx context.Context) string {
	if c.details != nil {
		return c.details(ctx)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.transcript, "\n")
}

// RestartsContainer reports whether the check's event names a container the
// supervisor should restart.
//
// watchdog.sh made this decision with the pattern `.+-mailcow` at the end of a
// long if/elif chain, so events that happen to end in -mailcow but were handled
// earlier — acme-mailcow — never reached it.
func (c *Check) RestartsContainer() bool {
	return strings.HasSuffix(c.Event, "-mailcow") && c.Event != "acme-mailcow"
}
