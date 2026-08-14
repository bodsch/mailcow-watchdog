package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// shutdownGrace bounds how long the server waits for in-flight scrapes.
const shutdownGrace = 5 * time.Second

// Readiness tracks whether the watchdog has finished starting up.
//
// The watchdog waits for MariaDB and Redis before it probes anything, which can
// take a while on a cold stack. /readyz stays negative until then so an
// orchestrator does not mistake "still waiting for the database" for "healthy".
type Readiness struct {
	ready atomic.Bool
}

// SetReady marks the watchdog as ready to serve.
func (r *Readiness) SetReady(ready bool) { r.ready.Store(ready) }

// Ready reports the current state.
func (r *Readiness) Ready() bool { return r.ready.Load() }

// Server exposes /metrics, /healthz and /readyz.
type Server struct {
	http      *http.Server
	readiness *Readiness
	log       *slog.Logger
}

// NewServer builds the observability endpoint. addr is empty to disable it, in
// which case NewServer returns nil.
func NewServer(addr string, gatherer prometheus.Gatherer, readiness *Readiness, log *slog.Logger) *Server {
	if addr == "" {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	if readiness == nil {
		readiness = &Readiness{}
	}

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{}))

	// Liveness only says the process is scheduling goroutines. It must not
	// depend on MariaDB or Redis, or a database outage would have the
	// orchestrator kill the very thing that reports on it.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writePlain(w, http.StatusOK, "ok")
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !readiness.Ready() {
			writePlain(w, http.StatusServiceUnavailable, "starting up")
			return
		}
		writePlain(w, http.StatusOK, "ready")
	})

	return &Server{
		http: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
		readiness: readiness,
		log:       log.With("component", "metrics"),
	}
}

// Run serves until ctx is cancelled, then shuts down gracefully.
//
// A listener that cannot be opened is reported as an error, because a silently
// missing metrics endpoint is worse than a loud startup failure.
func (s *Server) Run(ctx context.Context) error {
	if s == nil {
		return nil
	}

	errs := make(chan error, 1)
	go func() {
		s.log.Info("serving metrics", "addr", s.http.Addr)
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("serving metrics on %s: %w", s.http.Addr, err)
			return
		}
		errs <- nil
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()

		if err := s.http.Shutdown(shutdownCtx); err != nil {
			s.log.Warn("metrics server did not shut down cleanly", "err", err)
		}
		return nil
	}
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintln(w, body)
}
