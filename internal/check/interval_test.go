package check

import (
	"testing"
	"time"

	"bodsch.me/mailcow-watchdog/internal/config"
)

// TestIntervalsDefaultToTheShell pins the four windows to the numbers
// watchdog.sh slept, so that a stack which sets nothing keeps the cadence it had
// before this knob existed. An accidental change here would alter how fast every
// outage is noticed on every unconfigured installation.
func TestIntervalsDefaultToTheShell(t *testing.T) {
	w := Intervals(config.DefaultCheckInterval)

	tests := []struct {
		name string
		got  Interval
		want Interval
	}{
		// sleep $(( ( RANDOM % 60 ) + 20 ))
		{"standard", w.Standard, Interval{Min: 20 * time.Second, Max: 79 * time.Second}},
		// sleep $(( ( RANDOM % 120 ) + 20 ))
		{"clamd", w.Clamd, Interval{Min: 20 * time.Second, Max: 139 * time.Second}},
		{"external", w.External, Interval{Min: 30 * time.Minute, Max: 30*time.Minute + 19*time.Second}},
		// sleep 300
		{"cert", w.Cert, Interval{Min: 5 * time.Minute, Max: 5 * time.Minute}},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// TestIntervalsStretch is the point of the knob: a raised bound has to move the
// rounds, and it has to move them by what was asked for. Scaling the jitter with
// the interval would turn "every five minutes" into "somewhere between five and
// twenty minutes", which is a different request.
func TestIntervalsStretch(t *testing.T) {
	w := Intervals(5 * time.Minute)

	if want := (Interval{Min: 5 * time.Minute, Max: 5*time.Minute + 59*time.Second}); w.Standard != want {
		t.Errorf("standard = %v, want %v", w.Standard, want)
	}
	if want := (Interval{Min: 5 * time.Minute, Max: 5*time.Minute + 119*time.Second}); w.Clamd != want {
		t.Errorf("clamd = %v, want %v", w.Clamd, want)
	}
	// Still its own longer window: the configured bound is below it.
	if want := (Interval{Min: 30 * time.Minute, Max: 30*time.Minute + 19*time.Second}); w.External != want {
		t.Errorf("external = %v, want %v", w.External, want)
	}
	if want := Fixed(5 * time.Minute); w.Cert != want {
		t.Errorf("cert = %v, want %v", w.Cert, want)
	}
}

// TestIntervalsRaiseTheLongChecks: past a point the configured bound overtakes
// the two checks that had their own long sleeps. Leaving them behind would mean
// an operator who asked for hourly rounds still gets a certificate probe every
// five minutes — the one check whose notification is throttled to a day anyway.
func TestIntervalsRaiseTheLongChecks(t *testing.T) {
	w := Intervals(2 * time.Hour)

	if w.Cert.Min != 2*time.Hour || w.Cert.Max != 2*time.Hour {
		t.Errorf("cert = %v, want a flat 2h", w.Cert)
	}
	if w.External.Min != 2*time.Hour {
		t.Errorf("external.Min = %v, want 2h", w.External.Min)
	}
	if want := 2*time.Hour + 19*time.Second; w.External.Max != want {
		t.Errorf("external.Max = %v, want %v", w.External.Max, want)
	}
}

// TestIntervalsRefuseAZeroSleep is the expensive one. A window with Min 0 makes
// Pick return immediately, and nineteen checks then probe the stack in a tight
// loop — a watchdog that reads as configured and behaves like a load generator.
// config.Load rejects the value, but Intervals is exported and a Config built by
// hand in a test or a future caller would carry a zero.
func TestIntervalsRefuseAZeroSleep(t *testing.T) {
	for _, base := range []time.Duration{0, -time.Second, -time.Hour} {
		w := Intervals(base)
		for _, iv := range []struct {
			name string
			Interval
		}{
			{"standard", w.Standard}, {"clamd", w.Clamd},
			{"external", w.External}, {"cert", w.Cert},
		} {
			if iv.Min <= 0 {
				t.Errorf("Intervals(%v): %s.Min = %v, want a positive sleep", base, iv.name, iv.Min)
			}
			if got := iv.Pick(); got <= 0 {
				t.Errorf("Intervals(%v): %s.Pick() = %v, want a positive sleep", base, iv.name, got)
			}
		}
	}
}

// TestBuildCarriesTheConfiguredInterval closes the gap between deriving the
// windows and using them: the derivation could be right while Build still handed
// the checks the old constants, and no test above would notice.
func TestBuildCarriesTheConfiguredInterval(t *testing.T) {
	cfg := testConfig(t, map[string]string{"WATCHDOG_CHECK_INTERVAL": "4m"})

	checks, err := Build(Deps{
		Config:   cfg,
		Resolver: DNSResolver{},
		Store:    nil,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	want := Intervals(4 * time.Minute)
	seen := map[string]bool{}
	for _, c := range checks {
		seen[c.Name] = true
		switch c.Name {
		case "clamd":
			if c.Interval != want.Clamd {
				t.Errorf("clamd interval = %v, want %v", c.Interval, want.Clamd)
			}
		case "cert":
			if c.Interval != want.Cert {
				t.Errorf("cert interval = %v, want %v", c.Interval, want.Cert)
			}
		case "external":
			if c.Interval != want.External {
				t.Errorf("external interval = %v, want %v", c.Interval, want.External)
			}
		default:
			if c.Interval != want.Standard {
				t.Errorf("%s interval = %v, want %v", c.Name, c.Interval, want.Standard)
			}
		}
	}
	// A typo in a check name would make the switch above assert nothing.
	for _, name := range []string{"clamd", "cert", "nginx"} {
		if !seen[name] {
			t.Errorf("Build returned no %q check, so its interval was never asserted", name)
		}
	}
}

// TestDefaultCheckIntervalMatchesTheShell ties the constant config.Load defaults
// to and the one the windows are built from together. They are spelled out in
// two packages because config cannot import check, and a change to one alone
// would silently shift every unconfigured stack.
func TestDefaultCheckIntervalMatchesTheShell(t *testing.T) {
	if config.DefaultCheckInterval != originalInterval {
		t.Errorf("config.DefaultCheckInterval = %v, check.originalInterval = %v",
			config.DefaultCheckInterval, originalInterval)
	}

	cfg := testConfig(t, nil)
	if cfg.CheckInterval != originalInterval {
		t.Errorf("an unset WATCHDOG_CHECK_INTERVAL gives %v, want %v",
			cfg.CheckInterval, originalInterval)
	}
}
