package metrics

import (
	"testing"

	"bodsch.me/mailcow-watchdog/internal/health"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestObserveHealth(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, Build{Version: "test"})

	m.ObserveHealth("nginx", health.Snapshot{
		Service:   "Nginx",
		Threshold: 5,
		Remaining: 3,
		Percent:   60,
	})

	if got := testutil.ToFloat64(m.healthPercent.WithLabelValues("nginx")); got != 60 {
		t.Errorf("health percent = %v, want 60", got)
	}
	if got := testutil.ToFloat64(m.healthPoints.WithLabelValues("nginx")); got != 3 {
		t.Errorf("health points = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.threshold.WithLabelValues("nginx")); got != 5 {
		t.Errorf("threshold = %v, want 5", got)
	}
}

// A metric that only appears once something has gone wrong is hard to alert on,
// so every enabled check publishes a full budget at startup.
func TestInitCheckPublishesFullHealth(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, Build{Version: "test"})

	m.InitCheck("dovecot", 12)

	if got := testutil.ToFloat64(m.healthPercent.WithLabelValues("dovecot")); got != 100 {
		t.Errorf("health percent = %v, want 100", got)
	}
	if got := testutil.ToFloat64(m.healthPoints.WithLabelValues("dovecot")); got != 12 {
		t.Errorf("health points = %v, want 12", got)
	}
}

func TestObserveProbeCountsByStatus(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, Build{Version: "test"})

	m.ObserveProbe("dovecot", "imap-993", health.StatusOK, 0.02)
	m.ObserveProbe("dovecot", "imap-993", health.StatusCritical, 9.9)
	m.ObserveProbe("dovecot", "imap-993", health.StatusCritical, 10.1)

	if got := testutil.ToFloat64(m.probeTotal.WithLabelValues("dovecot", "imap-993", "OK")); got != 1 {
		t.Errorf("OK count = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.probeTotal.WithLabelValues("dovecot", "imap-993", "CRITICAL")); got != 2 {
		t.Errorf("CRITICAL count = %v, want 2", got)
	}
}

func TestCountersAndPausedGauge(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, Build{Version: "test"})

	m.ObserveExhausted("nginx")
	m.ObserveRestart("nginx-mailcow", "restarted")
	m.ObserveRestart("nginx-mailcow", "skipped")
	m.ObserveEvent("nginx-mailcow", "restart")
	m.ObserveNotification("sent")

	m.SetPaused(true)
	if got := testutil.ToFloat64(m.paused); got != 1 {
		t.Errorf("paused = %v, want 1", got)
	}
	m.SetPaused(false)
	if got := testutil.ToFloat64(m.paused); got != 0 {
		t.Errorf("paused = %v, want 0", got)
	}

	if got := testutil.ToFloat64(m.restarts.WithLabelValues("nginx-mailcow", "restarted")); got != 1 {
		t.Errorf("restart count = %v, want 1", got)
	}
}

func TestBuildInfo(t *testing.T) {
	reg := prometheus.NewRegistry()
	New(reg, Build{Version: "1.2.3", Date: "2026-08-17"})

	want := map[string]string{"version": "1.2.3", "build_date": "2026-08-17"}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "mailcow_watchdog_build_info" {
			continue
		}
		for _, metric := range family.GetMetric() {
			got := map[string]string{}
			for _, label := range metric.GetLabel() {
				got[label.GetName()] = label.GetValue()
			}
			for name, value := range want {
				if got[name] != value {
					t.Errorf("build_info label %s = %q, want %q", name, got[name], value)
				}
			}
			return
		}
	}
	t.Error("build_info was not exposed at all")
}

// The HTTP endpoints that expose these collectors live in internal/obs and are
// tested there.
