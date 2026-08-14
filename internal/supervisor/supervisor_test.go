package supervisor

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"bodsch.me/mailcow-watchdog/internal/check"
	"bodsch.me/mailcow-watchdog/internal/notify"
	"bodsch.me/mailcow-watchdog/internal/probe"
	"bodsch.me/mailcow-watchdog/internal/store/storetest"
)

// capture is a Notifier that records the messages it was asked to deliver.
type capture struct {
	mu   sync.Mutex
	sent []notify.Message
}

func (c *capture) Send(_ context.Context, msg notify.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, msg)
	return nil
}

func (c *capture) messages() []notify.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]notify.Message(nil), c.sent...)
}

// harness wires a supervisor up with fakes and exposes what they recorded.
type harness struct {
	sup      *Supervisor
	docker   *fakeDocker
	store    *storetest.Fake
	notifier *capture
	clock    *fakeClock
}

func newHarness(t *testing.T, checks []*check.Check, configure func(*Options)) *harness {
	t.Helper()

	h := &harness{
		docker:   newFakeDocker(),
		store:    storetest.New(),
		notifier: &capture{},
		clock:    newFakeClock(1 << 20),
	}

	opts := Options{
		Checks:  checks,
		Docker:  h.docker,
		Store:   h.store,
		Metrics: newMetrics(),
		Clock:   h.clock,
		Log:     discardLog(),
	}
	opts.Dispatcher = notify.NewDispatcher(h.notifier, h.store, "Watchdog ALERT", discardLog())

	if configure != nil {
		configure(&opts)
	}

	sup, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.sup = sup
	return h
}

// raise delivers one event to the supervisor's handler directly, which is what
// a runner does when its budget is spent.
func (h *harness) raise(t *testing.T, c *check.Check) {
	t.Helper()
	h.sup.handle(context.Background(), Event{Check: c, Snapshot: h.sup.byName[c.Name].Snapshot()})
}

func okCheck(name, event string) *check.Check {
	return testCheck(name, event, 5, newScriptedProbe("probe", probe.OK("fine")))
}

// Each notify-only event carries its own wording, which the shell spelled out in
// its main loop.
func TestNotifyOnlyEvents(t *testing.T) {
	tests := []struct {
		name        string
		event       string
		wantSubject string
		wantBody    string
	}{
		{
			name: "ratelimit", event: "ratelimit",
			wantSubject: "Watchdog ALERT: ratelimit",
			wantBody:    "Service was restarted on",
		},
		{
			name: "mail queue", event: "mail_queue_status",
			wantSubject: "Watchdog ALERT: mail_queue_status",
			wantBody:    "Service was restarted on",
		},
		{
			name: "open relay", event: "external_checks",
			wantSubject: "Watchdog ALERT: external_checks",
			wantBody:    "Please stop mailcow now and check your network configuration!",
		},
		{
			name: "sql replication", event: "mysql_repl_checks",
			wantSubject: "Watchdog ALERT: mysql_repl_checks",
			wantBody:    "Please check the SQL replication status",
		},
		{
			name: "dovecot replication", event: "dovecot_repl_checks",
			wantSubject: "Watchdog ALERT: dovecot_repl_checks",
			wantBody:    "Please check the Dovecot replicator status",
		},
		{
			name: "certificate", event: "certcheck",
			wantSubject: "Watchdog ALERT: certcheck",
			wantBody:    "Please renew your certificate",
		},
		{
			name: "acme", event: "acme-mailcow",
			wantSubject: "Watchdog ALERT: acme-mailcow",
			wantBody:    "Please check acme-mailcow for further information.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := okCheck(tc.name, tc.event)
			h := newHarness(t, []*check.Check{c}, nil)

			h.raise(t, c)

			sent := h.notifier.messages()
			if len(sent) != 1 {
				t.Fatalf("sent %d notifications, want 1", len(sent))
			}
			if sent[0].Subject != tc.wantSubject {
				t.Errorf("Subject = %q, want %q", sent[0].Subject, tc.wantSubject)
			}
			if !strings.Contains(sent[0].Body, tc.wantBody) {
				t.Errorf("Body = %q, want it to contain %q", sent[0].Body, tc.wantBody)
			}
			if got := h.docker.restarts(); len(got) != 0 {
				t.Errorf("restarted %v, want a notify-only event to restart nothing", got)
			}
		})
	}
}

// acme-mailcow ends in -mailcow, but the shell handled it before its container
// branch. Restarting the ACME client would abandon an in-flight order.
func TestACMEEventNeverRestarts(t *testing.T) {
	c := okCheck("acme", "acme-mailcow")
	h := newHarness(t, []*check.Check{c}, nil)
	h.docker.withContainer("acme-mailcow", "acme-id", origin.Add(-time.Hour))

	h.raise(t, c)

	if got := h.docker.restarts(); len(got) != 0 {
		t.Errorf("restarted %v, want nothing", got)
	}
}

func TestRestartHappyPath(t *testing.T) {
	c := okCheck("nginx", "nginx-mailcow")
	h := newHarness(t, []*check.Check{c}, nil)
	// Running for well over the minimum uptime.
	h.docker.withContainer("nginx-mailcow", "nginx-id", origin.Add(-time.Hour))

	h.raise(t, c)

	restarts := h.docker.restarts()
	if len(restarts) != 1 || restarts[0] != "nginx-id" {
		t.Fatalf("restarted %v, want [nginx-id]", restarts)
	}
	if len(h.notifier.messages()) != 1 {
		t.Error("a restart should be announced")
	}

	// The mailcow UI shows these alongside the health records. The hyphen is
	// gone because log messages are sanitised the way the shell sanitised them,
	// with `tr '\r\n%&;$"_[]{}-' ' '`.
	if _, err := h.store.FindEntry("Sent restart command to nginx mailcow"); err != nil {
		t.Errorf("the restart was not logged to Redis: %v", err)
	}

	// The gate must be open again afterwards, or every check would stay frozen.
	if h.sup.gate.Paused() {
		t.Error("the checks were left paused after the restart")
	}
}

// A container that has only just come up is either still starting or already
// crash-looping; restarting it again would only speed the loop up.
func TestRestartSkippedForAYoungContainer(t *testing.T) {
	c := okCheck("nginx", "nginx-mailcow")
	h := newHarness(t, []*check.Check{c}, nil)
	h.docker.withContainer("nginx-mailcow", "nginx-id", origin.Add(-30*time.Second))

	h.raise(t, c)

	if got := h.docker.restarts(); len(got) != 0 {
		t.Errorf("restarted %v, want the young container to be left alone", got)
	}
	if got := h.notifier.messages(); len(got) != 0 {
		t.Errorf("sent %d notifications, want none for a skipped restart", len(got))
	}
}

func TestRestartProceedsExactlyAtTheUptimeLimit(t *testing.T) {
	c := okCheck("nginx", "nginx-mailcow")
	h := newHarness(t, []*check.Check{c}, nil)
	h.docker.withContainer("nginx-mailcow", "nginx-id", origin.Add(-MinUptime))

	h.raise(t, c)

	if got := h.docker.restarts(); len(got) != 1 {
		t.Errorf("restarted %v, want the container at exactly the limit to be restarted", got)
	}
}

// Interrupting a schema migration is worse than a slow web UI.
func TestRestartSkippedWhilePHPFPMInitialisesTheDatabase(t *testing.T) {
	c := okCheck("php-fpm", check.PHPFPMService)
	h := newHarness(t, []*check.Check{c}, nil)
	h.docker.withContainer(check.PHPFPMService, "php-id", origin.Add(-time.Hour))
	h.docker.runningProcess = true

	h.raise(t, c)

	if got := h.docker.restarts(); len(got) != 0 {
		t.Errorf("restarted %v, want the migration to be left alone", got)
	}
	// The shell delayed the checks for a minute instead of restarting.
	found := false
	for _, d := range h.clock.sleeps() {
		if d == InitDBDelay {
			found = true
		}
	}
	if !found {
		t.Error("the checks were not delayed while the migration ran")
	}
}

// The same gate protects the checks around a restart that the shell protected
// with kill -STOP.
func TestRestartPausesAndSettles(t *testing.T) {
	c := okCheck("nginx", "nginx-mailcow")
	h := newHarness(t, []*check.Check{c}, nil)
	h.docker.withContainer("nginx-mailcow", "nginx-id", origin.Add(-time.Hour))

	h.raise(t, c)

	var pause, settle bool
	for _, d := range h.clock.sleeps() {
		switch d {
		case PauseBeforeRestart:
			pause = true
		case SettleAfterRestart:
			settle = true
		}
	}
	if !pause {
		t.Error("in-flight probes were not given time to finish before the restart")
	}
	if !settle {
		t.Error("the restarted container was not given time to settle")
	}
}

func TestRestartOfAnUnknownContainer(t *testing.T) {
	c := okCheck("nginx", "nginx-mailcow")
	h := newHarness(t, []*check.Check{c}, nil)

	h.raise(t, c)

	if got := h.docker.restarts(); len(got) != 0 {
		t.Errorf("restarted %v, want nothing", got)
	}
	if h.sup.gate.Paused() {
		t.Error("the checks were left paused after a failed lookup")
	}
}

func TestRestartFailureLeavesTheGateOpen(t *testing.T) {
	c := okCheck("nginx", "nginx-mailcow")
	h := newHarness(t, []*check.Check{c}, nil)
	h.docker.withContainer("nginx-mailcow", "nginx-id", origin.Add(-time.Hour))
	h.docker.restartErr = errBoom

	h.raise(t, c)

	if h.sup.gate.Paused() {
		t.Error("the checks were left paused after a failed restart")
	}
	if got := h.notifier.messages(); len(got) != 0 {
		t.Error("a failed restart should not be announced as a restart")
	}
}

// A scaled service has several containers, and all of them need restarting.
func TestRestartCoversEveryReplica(t *testing.T) {
	c := okCheck("sogo", "sogo-mailcow")
	h := newHarness(t, []*check.Check{c}, nil)
	h.docker.withContainer("sogo-mailcow", "sogo-1", origin.Add(-time.Hour))
	h.docker.withContainer("sogo-mailcow", "sogo-2", origin.Add(-time.Hour))

	h.raise(t, c)

	if got := h.docker.restarts(); len(got) != 2 {
		t.Errorf("restarted %v, want both replicas", got)
	}
}

// Bans are always logged, but only mailed when WATCHDOG_NOTIFY_BAN is set.
func TestFail2banNotifiesPerAddress(t *testing.T) {
	c := okCheck("fail2ban", "fail2ban")
	c.Bans = func() []string { return []string{"198.51.100.7", "203.0.113.9"} }

	h := newHarness(t, []*check.Check{c}, func(o *Options) {
		o.NotifyBans = true
		o.Whois = fakeWhois{record: "netname: EXAMPLE-NET"}
	})

	h.raise(t, c)

	sent := h.notifier.messages()
	if len(sent) != 2 {
		t.Fatalf("sent %d notifications, want one per address", len(sent))
	}
	// fail2ban is the one event whose subject carries the message.
	if !strings.Contains(sent[0].Subject, "IP ban: 198.51.100.7") {
		t.Errorf("Subject = %q, want the banned address", sent[0].Subject)
	}
	if !strings.Contains(sent[0].Body, "netname: EXAMPLE-NET") {
		t.Errorf("Body = %q, want the whois record", sent[0].Body)
	}
}

func TestFail2banStaysQuietWhenNotifyBanIsOff(t *testing.T) {
	c := okCheck("fail2ban", "fail2ban")
	c.Bans = func() []string { return []string{"198.51.100.7"} }

	h := newHarness(t, []*check.Check{c}, func(o *Options) {
		o.NotifyBans = false
		o.Whois = fakeWhois{record: "netname: EXAMPLE-NET"}
	})

	h.raise(t, c)

	if got := h.notifier.messages(); len(got) != 0 {
		t.Errorf("sent %d notifications, want none when WATCHDOG_NOTIFY_BAN is off", len(got))
	}
}

// A whois server being unreachable must not cost the operator the notification.
func TestFail2banSurvivesAFailingWhois(t *testing.T) {
	c := okCheck("fail2ban", "fail2ban")
	c.Bans = func() []string { return []string{"198.51.100.7"} }

	h := newHarness(t, []*check.Check{c}, func(o *Options) {
		o.NotifyBans = true
		o.Whois = fakeWhois{err: errBoom}
	})

	h.raise(t, c)

	sent := h.notifier.messages()
	if len(sent) != 1 {
		t.Fatalf("sent %d notifications, want 1", len(sent))
	}
	if !strings.Contains(sent[0].Subject, "IP ban: 198.51.100.7") {
		t.Errorf("Subject = %q", sent[0].Subject)
	}
}

// Without the dockerapi the watchdog cannot resolve container addresses, so
// every check would fail for a reason unrelated to the service it watches.
func TestDockerAPIWatcherPausesAndHeals(t *testing.T) {
	c := okCheck("nginx", "nginx-mailcow")
	h := newHarness(t, []*check.Check{c}, nil)

	runner := h.sup.byName["nginx"]
	runner.tracker.Record(4) // health 1 of 5

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h.docker.setReachable(false)

	done := make(chan struct{})
	go func() { h.sup.watchDockerAPI(ctx); close(done) }()

	waitFor(t, "the checks to be paused", func() bool { return h.sup.gate.Paused() })

	h.docker.setReachable(true)
	waitFor(t, "the checks to resume", func() bool { return !h.sup.gate.Paused() })

	// The check lost ground through no fault of the service it watches, so the
	// points are handed back.
	waitFor(t, "the error points to be repaid", func() bool {
		return runner.Snapshot().Remaining == 3
	})

	cancel()
	<-done
}

func TestNewRejectsAnEmptySetup(t *testing.T) {
	if _, err := New(Options{Metrics: newMetrics(), Store: storetest.New()}); err == nil {
		t.Error("New should reject a supervisor with no checks")
	}
	checks := []*check.Check{okCheck("nginx", "nginx-mailcow")}
	if _, err := New(Options{Checks: checks, Store: storetest.New()}); err == nil {
		t.Error("New should reject a supervisor without metrics")
	}
	if _, err := New(Options{Checks: checks, Metrics: newMetrics()}); err == nil {
		t.Error("New should reject a supervisor without a store")
	}
}

func TestSnapshot(t *testing.T) {
	c := okCheck("nginx", "nginx-mailcow")
	h := newHarness(t, []*check.Check{c}, nil)

	got := h.sup.Snapshot()
	if got["nginx"] != 100 {
		t.Errorf("Snapshot()[nginx] = %d, want 100", got["nginx"])
	}
}

// Run must start every check and stop them all when the context is cancelled.
func TestRunStartsAndStopsEveryCheck(t *testing.T) {
	first := newScriptedProbe("a", probe.OK("fine"))
	second := newScriptedProbe("b", probe.OK("fine"))

	checks := []*check.Check{
		testCheck("nginx", "nginx-mailcow", 5, first),
		testCheck("redis", "redis-mailcow", 5, second),
	}
	h := newHarness(t, checks, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.sup.Run(ctx) }()

	waitFor(t, "both checks to run", func() bool {
		return first.callCount() > 0 && second.callCount() > 0
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestShortID(t *testing.T) {
	if got := shortID("0123456789abcdef0123"); got != "0123456789ab" {
		t.Errorf("shortID = %q", got)
	}
	if got := shortID("abc"); got != "abc" {
		t.Errorf("shortID = %q, want short input to be left alone", got)
	}
}
