package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"bodsch.me/mailcow-watchdog/internal/config"
	"bodsch.me/mailcow-watchdog/internal/logging"
)

// config.Log and logging.Options are converted into one another, which only
// compiles while the two structs agree. This test pins the behaviour that
// conversion is supposed to carry: DEV_MODE's text output and the container
// default's JSON both arrive at the handler.
func TestLoggerIsBuiltFromTheConfig(t *testing.T) {
	tests := []struct {
		name  string
		cfg   config.Log
		wants string
	}{
		{"the container default", config.Log{Level: "info", Format: "json"}, `"msg":"hello"`},
		{"DEV_MODE", config.Log{Level: "debug", Format: "text"}, "msg=hello"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logging.New(&buf, logging.Options(tc.cfg)).Info("hello")

			if !strings.Contains(buf.String(), tc.wants) {
				t.Errorf("output %q does not contain %q", buf.String(), tc.wants)
			}
		})
	}

	// The level has to travel too, or DEV_MODE would be quiet.
	var buf bytes.Buffer
	log := logging.New(&buf, logging.Options(config.Log{Level: "error", Format: "json"}))
	if log.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("a warning should be filtered out at level error")
	}
}

// A failed listener has to reach run's caller rather than being lost in the
// goroutine that serves it.
func TestWaitForObsReportsTheServerError(t *testing.T) {
	failed := errors.New("serving metrics on :9393: address in use")

	done := make(chan error, 1)
	done <- failed

	if err := waitForObs(done); !errors.Is(err, failed) {
		t.Errorf("waitForObs = %v, want %v", err, failed)
	}
}

func TestSettleHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := settle(ctx, time.Hour, discardLog()); !errors.Is(err, context.Canceled) {
		t.Errorf("settle = %v, want context.Canceled", err)
	}
	// A zero delay is not a wait at all.
	if err := settle(ctx, 0, discardLog()); err != nil {
		t.Errorf("settle with no delay = %v, want nil", err)
	}
}

// Startup waits for MariaDB and Redis rather than letting every check fail
// identically on a cold stack.
func TestWaitForRetriesUntilAvailable(t *testing.T) {
	attempts := 0
	probe := func(context.Context) error {
		attempts++
		if attempts < 3 {
			return errors.New("connection refused")
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := waitFor(ctx, discardLog(), "SQL", probe); err != nil {
		t.Fatalf("waitFor: %v", err)
	}
	if attempts != 3 {
		t.Errorf("probed %d times, want 3", attempts)
	}
}

func TestWaitForStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	probe := func(context.Context) error { return errors.New("connection refused") }
	if err := waitFor(ctx, discardLog(), "Redis", probe); !errors.Is(err, context.Canceled) {
		t.Errorf("waitFor = %v, want context.Canceled", err)
	}
}

func TestResolverName(t *testing.T) {
	if got := resolverName(true); got != "dockerapi" {
		t.Errorf("resolverName(true) = %q", got)
	}
	if got := resolverName(false); got != "dns" {
		t.Errorf("resolverName(false) = %q", got)
	}
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
