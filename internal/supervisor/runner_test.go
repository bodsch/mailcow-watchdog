package supervisor

import (
	"context"
	"strings"
	"testing"
	"time"

	"bodsch.me/mailcow-watchdog/internal/check"
	"bodsch.me/mailcow-watchdog/internal/probe"
	"bodsch.me/mailcow-watchdog/internal/store/storetest"
)

// runRunner drives a runner until its clock runs out of budget and returns the
// events it raised.
func runRunner(t *testing.T, c *check.Check, clock *fakeClock, fake *storetest.Fake) []Event {
	t.Helper()

	events := make(chan Event, 16)
	r := NewRunner(c, RunnerDeps{
		Gate:    NewGate(),
		Clock:   clock,
		Store:   fake,
		Metrics: newMetrics(),
		Events:  events,
		Log:     discardLog(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the runner did not stop")
	}

	close(events)
	var raised []Event
	for e := range events {
		raised = append(raised, e)
	}
	return raised
}

// A healthy check writes one health record per round and never raises an event.
func TestRunnerHealthyRounds(t *testing.T) {
	p := newScriptedProbe("http", probe.OK("all good"))
	c := testCheck("nginx", "nginx-mailcow", 5, p)

	fake := storetest.New()
	clock := newFakeClock(3)

	if events := runRunner(t, c, clock, fake); len(events) != 0 {
		t.Errorf("raised %d events for a healthy check, want none", len(events))
	}
	if got := p.callCount(); got != 4 {
		// Three completed rounds plus the one whose sleep exhausted the budget.
		t.Errorf("probe ran %d times, want 4", got)
	}

	entries := fake.Entries()
	if len(entries) < 3 {
		t.Fatalf("wrote %d health records, want at least 3", len(entries))
	}
	if !strings.Contains(entries[0], `"hpnow":"5"`) {
		t.Errorf("health record = %s, want full health", entries[0])
	}
}

// Failures accumulate at the Nagios exit code's weight until the budget is
// spent, then the check raises its event and starts over.
func TestRunnerExhaustsBudgetAndResets(t *testing.T) {
	// Threshold 4, each round costs 2, so the event lands on the second round.
	p := newScriptedProbe("http", probe.Critical("connection refused"))
	c := testCheck("nginx", "nginx-mailcow", 4, p)

	fake := storetest.New()
	// Three rounds: spend half the budget, spend the rest and raise the event,
	// then one more round to observe the reset.
	clock := newFakeClock(2)

	events := runRunner(t, c, clock, fake)
	if len(events) != 1 {
		t.Fatalf("raised %d events, want 1", len(events))
	}
	if events[0].Check != c {
		t.Error("the event does not carry the check that raised it")
	}
	if !events[0].Snapshot.Dead() {
		t.Errorf("the event carries a live snapshot: %+v", events[0].Snapshot)
	}

	// The budget is reset after the event, so the round that follows starts
	// from full health again — the shell got this by returning from the check
	// function and being called anew. Entries are newest first, mirroring LPUSH.
	entries := fake.Entries()
	if len(entries) != 3 {
		t.Fatalf("wrote %d health records, want 3", len(entries))
	}
	if !strings.Contains(entries[0], `"hpnow":"2"`) {
		t.Errorf("the round after the event = %s, want the budget to have been reset", entries[0])
	}
	if !strings.Contains(entries[1], `"hpnow":"0"`) {
		t.Errorf("the round that raised the event = %s, want an exhausted budget", entries[1])
	}
}

// The sleep after a spent budget is the check's DeadDelay, not its interval:
// most services are worth rechecking immediately, replication is not.
func TestRunnerUsesDeadDelayAfterExhaustion(t *testing.T) {
	p := newScriptedProbe("probe", probe.Critical("down"))
	c := testCheck("nginx", "nginx-mailcow", 2, p)
	c.Interval = check.Fixed(30 * time.Second)
	c.DeadDelay = time.Second

	clock := newFakeClock(2)
	runRunner(t, c, clock, storetest.New())

	slept := clock.sleeps()
	if len(slept) == 0 {
		t.Fatal("the runner never slept")
	}
	if slept[0] != time.Second {
		t.Errorf("first sleep = %v, want the dead delay of 1s", slept[0])
	}
}

func TestRunnerUsesIntervalWhileHealthy(t *testing.T) {
	c := testCheck("nginx", "nginx-mailcow", 5, newScriptedProbe("probe", probe.OK("fine")))
	c.Interval = check.Fixed(30 * time.Second)

	clock := newFakeClock(2)
	runRunner(t, c, clock, storetest.New())

	for i, d := range clock.sleeps() {
		if d != 30*time.Second {
			t.Errorf("sleep %d = %v, want the 30s interval", i, d)
		}
	}
}

// A check with several probes sums their weights, exactly as the shell's
// repeated `err_count=$(( err_count + $? ))` did.
func TestRunnerSumsProbeWeights(t *testing.T) {
	warning := newScriptedProbe("warn", probe.Warning("degraded"))
	critical := newScriptedProbe("crit", probe.Critical("down"))
	c := testCheck("dovecot", "dovecot-mailcow", 10, warning, critical)

	fake := storetest.New()
	runRunner(t, c, newFakeClock(1), fake)

	// Entries are newest first, mirroring LPUSH, so the first round is last.
	entries := fake.Entries()
	if len(entries) == 0 {
		t.Fatal("no health record was written")
	}
	first := entries[len(entries)-1]

	// One round costs 1 + 2 = 3 points out of 10.
	if !strings.Contains(first, `"hpnow":"7"`) {
		t.Errorf("health record = %s, want 7 of 10 remaining", first)
	}
	if !strings.Contains(first, `"hpdiff":"-3"`) {
		t.Errorf("health record = %s, want a trend of -3", first)
	}
}

// Probe output becomes the notification body, capped the way the shell capped
// its /tmp files.
func TestRunnerRecordsProbeOutputAsTranscript(t *testing.T) {
	p := newScriptedProbe("http", probe.Critical("HTTP CRITICAL: connection refused"))
	c := testCheck("nginx", "nginx-mailcow", 10, p)

	runRunner(t, c, newFakeClock(1), storetest.New())

	details := c.Details(context.Background())
	if !strings.Contains(details, "HTTP CRITICAL: connection refused") {
		t.Errorf("transcript = %q, want the probe message", details)
	}
	if !strings.Contains(details, "CRITICAL:") {
		t.Errorf("transcript = %q, want the severity recorded", details)
	}
}

// Heal is what the shell's kill -USR1 was meant to do and never did.
func TestRunnerHeal(t *testing.T) {
	c := testCheck("nginx", "nginx-mailcow", 10, newScriptedProbe("probe", probe.OK("fine")))

	r := NewRunner(c, RunnerDeps{
		Gate:    NewGate(),
		Clock:   newFakeClock(0),
		Store:   storetest.New(),
		Metrics: newMetrics(),
		Events:  make(chan Event, 1),
		Log:     discardLog(),
	})

	r.tracker.Record(6)
	if got := r.Snapshot().Remaining; got != 4 {
		t.Fatalf("health = %d, want 4", got)
	}

	r.Heal(HealPoints)
	if got := r.Snapshot().Remaining; got != 6 {
		t.Errorf("health after Heal = %d, want 6", got)
	}
}

// The gate has to hold a runner between rounds, not interrupt it mid-probe.
func TestRunnerWaitsAtTheGate(t *testing.T) {
	p := newScriptedProbe("probe", probe.OK("fine"))
	c := testCheck("nginx", "nginx-mailcow", 5, p)

	gate := NewGate()
	gate.Pause()

	r := NewRunner(c, RunnerDeps{
		Gate:    gate,
		Clock:   newFakeClock(2),
		Store:   storetest.New(),
		Metrics: newMetrics(),
		Events:  make(chan Event, 4),
		Log:     discardLog(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	time.Sleep(50 * time.Millisecond)
	if got := p.callCount(); got != 0 {
		t.Errorf("probe ran %d times while the gate was closed, want 0", got)
	}

	gate.Resume()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the runner did not resume")
	}
	if p.callCount() == 0 {
		t.Error("the probe never ran after the gate opened")
	}
}

// Redis being unavailable must not stop a check: the restart logic does not
// depend on it.
func TestRunnerSurvivesAnUnwritableStore(t *testing.T) {
	fake := storetest.New()
	fake.Err = errBoom

	p := newScriptedProbe("probe", probe.OK("fine"))
	c := testCheck("nginx", "nginx-mailcow", 5, p)

	runRunner(t, c, newFakeClock(2), fake)
	if p.callCount() < 2 {
		t.Errorf("probe ran %d times, want the check to have kept going", p.callCount())
	}
}

func TestRunnerName(t *testing.T) {
	c := testCheck("nginx", "nginx-mailcow", 5, newScriptedProbe("probe", probe.OK("fine")))
	r := NewRunner(c, RunnerDeps{
		Gate: NewGate(), Clock: newFakeClock(0), Store: storetest.New(),
		Metrics: newMetrics(), Events: make(chan Event, 1), Log: discardLog(),
	})

	if r.Name() != "nginx" {
		t.Errorf("Name() = %q, want nginx", r.Name())
	}
	if got := r.Snapshot(); got.Remaining != 5 || got.Dead() {
		t.Errorf("a fresh runner should start at full health, got %+v", got)
	}
}
