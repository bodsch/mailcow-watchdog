package metrics

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"bodsch.me/mailcow-watchdog/internal/health"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestObserveHealth(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, "test")

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
	m := New(reg, "test")

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
	m := New(reg, "test")

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
	m := New(reg, "test")

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
	New(reg, "1.2.3")

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "mailcow_watchdog_build_info" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "version" && label.GetValue() == "1.2.3" {
					return
				}
			}
		}
	}
	t.Error("build_info does not carry the version")
}

func TestServerEndpoints(t *testing.T) {
	reg := prometheus.NewRegistry()
	New(reg, "test")

	readiness := &Readiness{}
	addr := freeAddr(t)
	srv := NewServer(addr, reg, readiness, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	waitForListener(t, addr)

	// Liveness must not depend on the database or Redis, or an outage would have
	// the orchestrator kill the thing that reports on it.
	if code, _ := get(t, "http://"+addr+"/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", code)
	}

	// Readiness stays negative while the watchdog waits for its dependencies.
	if code, _ := get(t, "http://"+addr+"/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz = %d before startup finished, want 503", code)
	}
	readiness.SetReady(true)
	if code, _ := get(t, "http://"+addr+"/readyz"); code != http.StatusOK {
		t.Errorf("/readyz = %d after startup, want 200", code)
	}

	code, body := get(t, "http://"+addr+"/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics = %d, want 200", code)
	}
	if !strings.Contains(body, "mailcow_watchdog_build_info") {
		t.Errorf("/metrics does not expose the watchdog's metrics:\n%s", body)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
}

func TestNewServerDisabled(t *testing.T) {
	if NewServer("", prometheus.NewRegistry(), nil, nil) != nil {
		t.Error("an empty listen address should disable the server")
	}
	// A nil server must still be safe to run.
	var srv *Server
	if err := srv.Run(context.Background()); err != nil {
		t.Errorf("Run on a nil server = %v, want nil", err)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()

	for i := 0; i < 100; i++ {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("nothing started listening on %s", addr)
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", url, err)
	}
	return resp.StatusCode, string(body)
}
