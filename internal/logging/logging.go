// Package logging builds the service's structured logger.
//
// The factory below is shared with mailcow-dockerapi, which adds one further
// format for compatibility with the Python implementation it replaces. Keep both
// copies in sync — see CONVENTIONS.md.
package logging

import (
	"io"
	"log/slog"
)

// Options selects the level and the output format. It mirrors config.Log field
// for field, so main can convert one into the other — logging deliberately does
// not import the configuration package.
type Options struct {
	// Level is debug, info, warn or error. Anything else means info.
	Level string
	// Format is json or text. Anything else means json.
	Format string
}

// New returns a logger writing to w.
func New(w io.Writer, opts Options) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{Level: Level(opts.Level)}

	if opts.Format == "text" {
		return slog.New(slog.NewTextHandler(w, handlerOpts))
	}
	return slog.New(slog.NewJSONHandler(w, handlerOpts))
}

// Level maps a configured level name onto its slog level. An unknown name is
// info, so a typo makes the service chattier rather than silent.
func Level(name string) slog.Level {
	switch name {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
