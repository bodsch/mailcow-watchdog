package check

import (
	"context"
	"strings"
	"testing"
	"time"

	"bodsch.me/mailcow-watchdog/internal/config"
	"bodsch.me/mailcow-watchdog/internal/store/storetest"
)

func testConfig(t *testing.T, overrides map[string]string) *config.Config {
	t.Helper()

	envs := map[string]string{
		"MAILCOW_HOSTNAME":     "mail.example.org",
		"COMPOSE_PROJECT_NAME": "mailcowdockerized",
		"DBUSER":               "mailcow",
		"DBPASS":               "secret",
		"DBNAME":               "mailcow",
		"DBROOT":               "rootpw",
	}
	for k, v := range overrides {
		envs[k] = v
	}

	cfg, err := config.Load(func(key string) (string, bool) {
		v, ok := envs[key]
		return v, ok
	})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func build(t *testing.T, overrides map[string]string) []*Check {
	t.Helper()

	checks, err := Build(Deps{
		Config:   testConfig(t, overrides),
		Resolver: DNSResolver{},
		Store:    storetest.New(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return checks
}

func byName(checks []*Check) map[string]*Check {
	out := make(map[string]*Check, len(checks))
	for _, c := range checks {
		out[c.Name] = c
	}
	return out
}

// Every check that watchdog.sh spawned unconditionally must be present, and the
// opt-in ones must stay off until they are asked for.
func TestBuildDefaultSelection(t *testing.T) {
	checks := build(t, nil)
	got := byName(checks)

	alwaysOn := []string{
		"nginx", "mysql", "redis", "php-fpm", "sogo", "unbound", "clamd",
		"postfix", "mailq", "postfix-tlspol", "dovecot", "dovecot-repl",
		"rspamd", "ratelimit", "fail2ban", "cert", "olefy", "acme",
	}
	for _, name := range alwaysOn {
		if _, ok := got[name]; !ok {
			t.Errorf("check %q is missing from the default set", name)
		}
	}

	for _, name := range []string{"external", "mysql-repl"} {
		if _, ok := got[name]; ok {
			t.Errorf("check %q should be opt-in, but is enabled by default", name)
		}
	}
}

func TestBuildHonoursTheOptInFlags(t *testing.T) {
	checks := build(t, map[string]string{
		"WATCHDOG_EXTERNAL_CHECKS":          "y",
		"WATCHDOG_MYSQL_REPLICATION_CHECKS": "y",
	})
	got := byName(checks)

	if _, ok := got["external"]; !ok {
		t.Error("WATCHDOG_EXTERNAL_CHECKS=y should enable the external check")
	}
	if _, ok := got["mysql-repl"]; !ok {
		t.Error("WATCHDOG_MYSQL_REPLICATION_CHECKS=y should enable the replication check")
	}
}

func TestBuildHonoursTheSkipFlags(t *testing.T) {
	checks := build(t, map[string]string{
		"SKIP_SOGO":     "y",
		"SKIP_CLAMD":    "y",
		"SKIP_OLEFY":    "y",
		"CHECK_UNBOUND": "0",
	})
	got := byName(checks)

	for _, name := range []string{"sogo", "clamd", "olefy", "unbound"} {
		if _, ok := got[name]; ok {
			t.Errorf("check %q should have been skipped", name)
		}
	}
}

// Every enabled check must actually probe something, or it would sit in its loop
// reporting perfect health forever.
func TestEveryEnabledCheckHasProbes(t *testing.T) {
	checks := build(t, map[string]string{
		"WATCHDOG_EXTERNAL_CHECKS":          "y",
		"WATCHDOG_MYSQL_REPLICATION_CHECKS": "y",
	})

	for _, c := range checks {
		if len(c.Probes) == 0 {
			t.Errorf("check %q has no probes", c.Name)
		}
		if c.Threshold < 1 {
			t.Errorf("check %q has threshold %d", c.Name, c.Threshold)
		}
		if c.Event == "" {
			t.Errorf("check %q has no event name", c.Name)
		}
		if c.Service == "" {
			t.Errorf("check %q has no display name", c.Name)
		}
		if c.Interval.Min <= 0 {
			t.Errorf("check %q has a non-positive interval", c.Name)
		}
	}
}

// The display names end up in WATCHDOG_LOG and the mailcow UI renders them
// verbatim, so they have to match what the shell wrote.
func TestServiceNamesMatchTheShell(t *testing.T) {
	want := map[string]string{
		"nginx":          "Nginx",
		"unbound":        "Unbound",
		"redis":          "Redis",
		"mysql":          "MySQL/MariaDB",
		"mysql-repl":     "MySQL/MariaDB replication",
		"sogo":           "SOGo",
		"postfix":        "Postfix",
		"postfix-tlspol": "Postfix TLS Policy companion",
		"clamd":          "Clamd",
		"dovecot":        "Dovecot",
		"dovecot-repl":   "Dovecot replication",
		"cert":           "Primary certificate expiry check",
		"php-fpm":        "PHP-FPM",
		"ratelimit":      "Ratelimit",
		"mailq":          "Mail queue",
		"fail2ban":       "Fail2ban",
		"acme":           "ACME",
		"rspamd":         "Rspamd",
		"olefy":          "Olefy",
		"external":       "External checks",
	}

	checks := build(t, map[string]string{
		"WATCHDOG_EXTERNAL_CHECKS":          "y",
		"WATCHDOG_MYSQL_REPLICATION_CHECKS": "y",
	})
	got := byName(checks)

	for name, service := range want {
		c, ok := got[name]
		if !ok {
			t.Errorf("check %q is missing", name)
			continue
		}
		if c.Service != service {
			t.Errorf("check %q reports as %q, want %q", name, c.Service, service)
		}
	}
}

// The event names are the strings the shell pushed through its FIFO, and the
// supervisor still branches on them.
func TestEventNamesMatchTheShell(t *testing.T) {
	want := map[string]string{
		"nginx":          "nginx-mailcow",
		"unbound":        "unbound-mailcow",
		"redis":          "redis-mailcow",
		"mysql":          "mysql-mailcow",
		"mysql-repl":     "mysql_repl_checks",
		"sogo":           "sogo-mailcow",
		"postfix":        "postfix-mailcow",
		"postfix-tlspol": "postfix-tlspol-mailcow",
		"clamd":          "clamd-mailcow",
		"dovecot":        "dovecot-mailcow",
		"dovecot-repl":   "dovecot_repl_checks",
		"cert":           "certcheck",
		"php-fpm":        "php-fpm-mailcow",
		"ratelimit":      "ratelimit",
		"mailq":          "mail_queue_status",
		"fail2ban":       "fail2ban",
		"acme":           "acme-mailcow",
		"rspamd":         "rspamd-mailcow",
		"olefy":          "olefy-mailcow",
		"external":       "external_checks",
	}

	checks := build(t, map[string]string{
		"WATCHDOG_EXTERNAL_CHECKS":          "y",
		"WATCHDOG_MYSQL_REPLICATION_CHECKS": "y",
	})
	got := byName(checks)

	for name, event := range want {
		c, ok := got[name]
		if !ok {
			continue
		}
		if c.Event != event {
			t.Errorf("check %q raises %q, want %q", name, c.Event, event)
		}
	}
}

// acme-mailcow ends in -mailcow but the shell handled it before its container
// branch, so it notifies and never restarts anything.
func TestRestartsContainer(t *testing.T) {
	tests := map[string]bool{
		"nginx":      true,
		"dovecot":    true,
		"php-fpm":    true,
		"acme":       false,
		"cert":       false,
		"ratelimit":  false,
		"fail2ban":   false,
		"mailq":      false,
		"mysql-repl": false,
	}

	checks := build(t, map[string]string{"WATCHDOG_MYSQL_REPLICATION_CHECKS": "y"})
	got := byName(checks)

	for name, want := range tests {
		c, ok := got[name]
		if !ok {
			t.Errorf("check %q is missing", name)
			continue
		}
		if c.RestartsContainer() != want {
			t.Errorf("check %q RestartsContainer() = %v, want %v", name, c.RestartsContainer(), want)
		}
	}
}

// The sleeps were tuned per service in the shell and the outliers matter: the
// external relay test runs twice an hour, not twice a minute.
func TestIntervalsMatchTheShell(t *testing.T) {
	checks := build(t, map[string]string{"WATCHDOG_EXTERNAL_CHECKS": "y"})
	got := byName(checks)

	tests := []struct {
		name     string
		min, max time.Duration
	}{
		{"nginx", 20 * time.Second, 79 * time.Second},
		{"clamd", 20 * time.Second, 139 * time.Second},
		{"external", 30 * time.Minute, 30*time.Minute + 19*time.Second},
		{"cert", 5 * time.Minute, 5 * time.Minute},
	}
	for _, tc := range tests {
		c, ok := got[tc.name]
		if !ok {
			t.Errorf("check %q is missing", tc.name)
			continue
		}
		if c.Interval.Min != tc.min || c.Interval.Max != tc.max {
			t.Errorf("check %q interval = [%v, %v], want [%v, %v]",
				tc.name, c.Interval.Min, c.Interval.Max, tc.min, tc.max)
		}
	}
}

func TestIntervalPickStaysInRange(t *testing.T) {
	window := Interval{Min: 20 * time.Second, Max: 79 * time.Second}

	seen := map[time.Duration]bool{}
	for i := 0; i < 500; i++ {
		got := window.Pick()
		if got < window.Min || got > window.Max {
			t.Fatalf("Pick() = %v, outside [%v, %v]", got, window.Min, window.Max)
		}
		seen[got] = true
	}
	// The jitter exists to stagger the checks; a constant would defeat it.
	if len(seen) < 10 {
		t.Errorf("Pick() produced only %d distinct values, want a spread", len(seen))
	}

	if got := Fixed(time.Minute).Pick(); got != time.Minute {
		t.Errorf("Fixed(1m).Pick() = %v, want 1m", got)
	}
}

// The transcript is what the notification body falls back to, capped the way the
// shell capped its /tmp files with `tail -50`.
func TestTranscriptKeepsTheLastFiftyLines(t *testing.T) {
	c := &Check{Name: "nginx"}

	for i := 0; i < 120; i++ {
		c.Record(strings.Repeat("x", 1) + " line " + string(rune('a'+i%26)))
	}

	lines := strings.Split(c.Details(context.Background()), "\n")
	if len(lines) != transcriptLines {
		t.Errorf("transcript holds %d lines, want %d", len(lines), transcriptLines)
	}
}

func TestTranscriptSkipsEmptyLines(t *testing.T) {
	c := &Check{Name: "nginx"}
	c.Record("first", "", "second")

	if got := c.Details(context.Background()); got != "first\nsecond" {
		t.Errorf("Details() = %q, want the empty line dropped", got)
	}
}

// The ratelimit and external checks report their own body rather than the probe
// transcript.
func TestStatefulChecksSupplyTheirOwnDetails(t *testing.T) {
	fake := storetest.New()
	fake.SetList("RL_LOG", `{"qid":"AAA111"}`)

	checks, err := Build(Deps{
		Config:   testConfig(t, nil),
		Resolver: DNSResolver{},
		Store:    fake,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	rl, ok := byName(checks)["ratelimit"]
	if !ok {
		t.Fatal("the ratelimit check is missing")
	}
	// Nothing was recorded into the transcript, so a plain check would return
	// an empty body here.
	details := rl.Details(context.Background())
	if !strings.Contains(details, "AAA111") {
		t.Errorf("Details() = %q, want the RL_LOG dump", details)
	}
}

func TestFail2banExposesItsBans(t *testing.T) {
	fake := storetest.New()
	checks, err := Build(Deps{
		Config:   testConfig(t, nil),
		Resolver: DNSResolver{},
		Store:    fake,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	f2b, ok := byName(checks)["fail2ban"]
	if !ok {
		t.Fatal("the fail2ban check is missing")
	}
	if f2b.Bans == nil {
		t.Fatal("the fail2ban check must expose its bans for per-address notifications")
	}
	if got := f2b.Bans(); len(got) != 0 {
		t.Errorf("Bans() = %v before any round, want none", got)
	}
}

func TestBuildRejectsMissingDependencies(t *testing.T) {
	if _, err := Build(Deps{Resolver: DNSResolver{}}); err == nil {
		t.Error("Build should require a configuration")
	}
	if _, err := Build(Deps{Config: testConfig(t, nil)}); err == nil {
		t.Error("Build should require a resolver")
	}
}

// The registry and the configuration must agree on the set of check names, or a
// check would silently never run.
func TestRegistryAndConfigAgreeOnNames(t *testing.T) {
	cfg := testConfig(t, map[string]string{
		"WATCHDOG_EXTERNAL_CHECKS":          "y",
		"WATCHDOG_MYSQL_REPLICATION_CHECKS": "y",
	})
	checks, err := Build(Deps{Config: cfg, Resolver: DNSResolver{}, Store: storetest.New()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(checks) != len(cfg.Checks.All()) {
		t.Errorf("Build returned %d checks, but the configuration knows %d",
			len(checks), len(cfg.Checks.All()))
	}
}
