// Package obs serves the observability endpoints: /metrics, /healthz and
// /readyz.
//
// This package is shared with mailcow-watchdog and is identical in both
// repositories. Keep both copies in sync — see CONVENTIONS.md.
package obs

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

// Readiness tracks whether the service has finished starting up.
//
// A service usually waits for Redis, a database or the Docker daemon before it
// can do its job, which can take a while on a cold stack. /readyz stays negative
// until then, so an orchestrator does not mistake "still connecting" for
// "healthy".
type Readiness struct {
	ready atomic.Bool
}

// SetReady marks the service as ready to serve.
func (r *Readiness) SetReady(ready bool) { r.ready.Store(ready) }

// Ready reports the current state.
func (r *Readiness) Ready() bool { return r.ready.Load() }

// Options configures the server.
type Options struct {
	// Listen is the address to bind. Empty disables the server entirely, in
	// which case New returns nil and Run is a no-op.
	Listen string
	// Gatherer supplies the metrics. It is passed in rather than defaulting to
	// the global registry, so a test can scrape its own.
	Gatherer prometheus.Gatherer
	// Readiness drives /readyz. When nil, a fresh one is used and the service
	// never reports ready.
	Readiness *Readiness
	Log       *slog.Logger
}

// Server exposes /metrics, /healthz and /readyz.
type Server struct {
	http *http.Server
	log  *slog.Logger
}

// New builds the observability endpoint. It returns nil when opts.Listen is
// empty.
func New(opts Options) *Server {
	if opts.Listen == "" {
		return nil
	}

	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	readiness := opts.Readiness
	if readiness == nil {
		readiness = &Readiness{}
	}

	mux := http.NewServeMux()

	if opts.Gatherer != nil {
		mux.Handle("GET /metrics", promhttp.HandlerFor(opts.Gatherer, promhttp.HandlerOpts{}))
	}

	// Liveness only says the process is scheduling goroutines. It must not
	// depend on Redis, a database or the Docker daemon, or an outage there would
	// have the orchestrator kill the very thing that reports on it.
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
			Addr:              opts.Listen,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
		log: log.With("component", "obs"),
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
			s.log.Warn("the metrics server did not shut down cleanly", "err", err)
		}
		return nil
	}
}

// Addr reports the address the server binds, for tests and startup logs.
func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	return s.http.Addr
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintln(w, body)
}
