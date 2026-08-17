package obs

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestServerEndpoints(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_gauge",
		Help: "A metric that only exists so the scrape has something to return.",
	}))

	readiness := &Readiness{}
	addr := freeAddr(t)
	srv := New(Options{Listen: addr, Gatherer: reg, Readiness: readiness})

	if got := srv.Addr(); got != addr {
		t.Errorf("Addr = %q, want %q", got, addr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	waitForListener(t, addr)

	// Liveness must not depend on any dependency, or an outage would have the
	// orchestrator kill the thing that reports on it.
	if code, _ := get(t, "http://"+addr+"/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", code)
	}

	// Readiness stays negative while the service is still connecting.
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
	if !strings.Contains(body, "probe_gauge") {
		t.Errorf("/metrics does not expose the registered collectors:\n%s", body)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
}

func TestNewDisabled(t *testing.T) {
	if New(Options{Gatherer: prometheus.NewRegistry()}) != nil {
		t.Error("an empty listen address should disable the server")
	}

	// A nil server must still be safe to use.
	var srv *Server
	if err := srv.Run(context.Background()); err != nil {
		t.Errorf("Run on a nil server = %v, want nil", err)
	}
	if got := srv.Addr(); got != "" {
		t.Errorf("Addr on a nil server = %q, want empty", got)
	}
}

// Without a gatherer the health endpoints still work; only /metrics is absent.
func TestServerWithoutAGatherer(t *testing.T) {
	addr := freeAddr(t)
	srv := New(Options{Listen: addr})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	waitForListener(t, addr)

	if code, _ := get(t, "http://"+addr+"/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", code)
	}
	if code, _ := get(t, "http://"+addr+"/metrics"); code != http.StatusNotFound {
		t.Errorf("/metrics = %d, want 404", code)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
}

// An address that cannot be bound has to surface as an error: a silently missing
// metrics endpoint is worse than a loud startup failure.
func TestRunReportsABrokenListener(t *testing.T) {
	srv := New(Options{Listen: "127.0.0.1:1"})

	err := srv.Run(context.Background())
	if err == nil {
		t.Fatal("Run: expected an error for a privileged port")
	}
	if !strings.Contains(err.Error(), "serving metrics") {
		t.Errorf("Run: error %q does not name the operation", err)
	}
}

// A URL where a bind address belongs is the mistake the variable's name invites,
// and net.Listen rejects it. What must not happen is the process logging that it
// serves metrics anyway: a scrape then gets a reset connection — through a
// published port, a refused one looks exactly like that — and the log says
// nothing.
func TestRunRejectsAURLAsAnAddress(t *testing.T) {
	var logged bytes.Buffer
	srv := New(Options{
		Listen: "http://127.0.0.1:9393/metrics",
		Log:    slog.New(slog.NewJSONHandler(&logged, nil)),
	})

	if err := srv.Run(context.Background()); err == nil {
		t.Fatal("Run: expected an error for a URL instead of a host:port address")
	}

	if got := logged.String(); strings.Contains(got, "serving metrics") {
		t.Errorf("the log claims the endpoint is being served: %q", got)
	}
	if got := logged.String(); !strings.Contains(got, "cannot bind the metrics endpoint") {
		t.Errorf("the bind failure never reached the log: %q", got)
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
