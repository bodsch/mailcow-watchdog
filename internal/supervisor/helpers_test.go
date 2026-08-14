package supervisor

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"bodsch.me/mailcow-watchdog/internal/check"
	"bodsch.me/mailcow-watchdog/internal/dockerapi"
	"bodsch.me/mailcow-watchdog/internal/metrics"
	"bodsch.me/mailcow-watchdog/internal/probe"
	"github.com/prometheus/client_golang/prometheus"
)

// origin is the fake clock's starting instant.
var origin = time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)

// fakeClock advances virtual time instantly, so a check whose interval is half a
// minute costs a test nothing. After budget sleeps it starts returning an error,
// which is how a runner's loop is brought to a halt.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	slept  []time.Duration
	budget int
}

func newFakeClock(budget int) *fakeClock {
	return &fakeClock{now: origin, budget: budget}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if c.budget <= 0 {
		return context.Canceled
	}
	c.budget--
	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
	return nil
}

// sleeps returns the recorded durations.
func (c *fakeClock) sleeps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.slept...)
}

// scriptedProbe returns results from a list, repeating the last one once the
// list runs out.
type scriptedProbe struct {
	name string

	mu      sync.Mutex
	results []probe.Result
	calls   int
}

func newScriptedProbe(name string, results ...probe.Result) *scriptedProbe {
	return &scriptedProbe{name: name, results: results}
}

func (p *scriptedProbe) Name() string { return p.name }

func (p *scriptedProbe) Run(context.Context) probe.Result {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls++
	if len(p.results) == 0 {
		return probe.OK("nothing scripted")
	}
	if p.calls <= len(p.results) {
		return p.results[p.calls-1]
	}
	return p.results[len(p.results)-1]
}

func (p *scriptedProbe) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// fakeDocker records what the supervisor asked it to do.
type fakeDocker struct {
	mu sync.Mutex

	containers map[string][]dockerapi.Container
	// runningProcess makes Running report true for any query.
	runningProcess bool
	// reachable drives the dockerapi watcher.
	reachable bool
	// findErr, when set, makes Find fail.
	findErr error
	// restartErr, when set, makes Restart fail.
	restartErr error

	restarted []string
	reachCall int
}

func newFakeDocker() *fakeDocker {
	return &fakeDocker{
		containers: map[string][]dockerapi.Container{},
		reachable:  true,
	}
}

// withContainer registers a container for a service, started at the given time.
func (d *fakeDocker) withContainer(service, id string, startedAt time.Time) *fakeDocker {
	d.mu.Lock()
	defer d.mu.Unlock()

	c := dockerapi.Container{ID: id, Service: service}
	if !startedAt.IsZero() {
		c.StartedAt = startedAt.Format(time.RFC3339Nano)
	}
	d.containers[service] = append(d.containers[service], c)
	return d
}

func (d *fakeDocker) Find(_ context.Context, service string) ([]dockerapi.Container, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.findErr != nil {
		return nil, d.findErr
	}
	return d.containers[service], nil
}

func (d *fakeDocker) Restart(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.restartErr != nil {
		return d.restartErr
	}
	d.restarted = append(d.restarted, id)
	return nil
}

func (d *fakeDocker) Running(_ context.Context, _, _ string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.runningProcess, nil
}

func (d *fakeDocker) Reachable(context.Context) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.reachCall++
	return d.reachable
}

func (d *fakeDocker) setReachable(reachable bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reachable = reachable
}

func (d *fakeDocker) restarts() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.restarted...)
}

// fakeWhois returns a canned registry record.
type fakeWhois struct {
	record string
	err    error
}

func (w fakeWhois) Lookup(context.Context, string) (string, error) {
	if w.err != nil {
		return "", w.err
	}
	return w.record, nil
}

// discardLog keeps test output readable.
func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// newMetrics builds a metrics set on a private registry.
func newMetrics() *metrics.Metrics {
	return metrics.New(prometheus.NewRegistry(), "test")
}

// testCheck builds a check with the given probes and short timings.
func testCheck(name, event string, threshold int, probes ...probe.Probe) *check.Check {
	return &check.Check{
		Name:      name,
		Service:   name,
		Event:     event,
		Threshold: threshold,
		Probes:    probes,
		Interval:  check.Fixed(30 * time.Second),
		DeadDelay: time.Second,
	}
}

var errBoom = errors.New("boom")
