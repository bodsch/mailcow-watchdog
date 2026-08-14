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
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name     string
		cfg      config.Log
		level    slog.Level
		enabled  bool
		contains string
	}{
		{
			name:     "json at info",
			cfg:      config.Log{Level: "info", Format: "json"},
			level:    slog.LevelInfo,
			enabled:  true,
			contains: `"msg"`,
		},
		{
			name:    "debug is filtered out at info",
			cfg:     config.Log{Level: "info", Format: "json"},
			level:   slog.LevelDebug,
			enabled: false,
		},
		{
			name:     "text at debug",
			cfg:      config.Log{Level: "debug", Format: "text"},
			level:    slog.LevelDebug,
			enabled:  true,
			contains: "msg=",
		},
		{
			name:    "error only",
			cfg:     config.Log{Level: "error", Format: "json"},
			level:   slog.LevelWarn,
			enabled: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log := newLogger(tc.cfg)
			if got := log.Enabled(context.Background(), tc.level); got != tc.enabled {
				t.Errorf("Enabled(%v) = %v, want %v", tc.level, got, tc.enabled)
			}
		})
	}
}

// The format has to be selectable because DEV_MODE turns on human-readable
// output while the container default is machine-readable.
func TestLoggerFormat(t *testing.T) {
	var buf bytes.Buffer

	json := slog.New(slog.NewJSONHandler(&buf, nil))
	json.Info("hello", "key", "value")
	if !strings.Contains(buf.String(), `"key":"value"`) {
		t.Errorf("JSON handler produced %q", buf.String())
	}

	buf.Reset()
	text := slog.New(slog.NewTextHandler(&buf, nil))
	text.Info("hello", "key", "value")
	if !strings.Contains(buf.String(), "key=value") {
		t.Errorf("text handler produced %q", buf.String())
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
