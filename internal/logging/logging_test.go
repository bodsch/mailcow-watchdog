package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestFormatSelection(t *testing.T) {
	tests := []struct {
		format string
		wants  string
	}{
		{"json", `"msg":"hello"`},
		{"text", `msg=hello`},
		// json is the default, because the watchdog's output is read by a log
		// collector rather than by a person.
		{"", `"msg":"hello"`},
		{"nonsense", `"msg":"hello"`},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var buf bytes.Buffer
			New(&buf, Options{Level: "info", Format: tt.format}).Info("hello")

			if !strings.Contains(buf.String(), tt.wants) {
				t.Errorf("output %q does not contain %q", buf.String(), tt.wants)
			}
		})
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, Options{Level: "info", Format: "text"})

	logger.Debug("not visible")
	if buf.Len() != 0 {
		t.Errorf("debug was written: %q", buf.String())
	}

	logger.Info("visible")
	if !strings.Contains(buf.String(), "visible") {
		t.Errorf("info is missing: %q", buf.String())
	}
}

// DEV_MODE and WATCHDOG_VERBOSE both map onto debug, so the level has to reach
// the handler.
func TestDebugLevelIsHonoured(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, Options{Level: "debug", Format: "text"}).Debug("probe transcript")

	if !strings.Contains(buf.String(), "probe transcript") {
		t.Errorf("debug was not written: %q", buf.String())
	}
}

func TestLevelNames(t *testing.T) {
	tests := []struct {
		name string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo},
		{"chatty", slog.LevelInfo},
	}

	for _, tt := range tests {
		if got := Level(tt.name); got != tt.want {
			t.Errorf("Level(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
