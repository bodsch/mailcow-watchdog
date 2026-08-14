package supervisor

import (
	"context"
	"sync"
	"time"
)

// Gate holds every check runner while the supervisor is doing something that
// would otherwise make all of their probes fail for the same uninteresting
// reason — restarting a container, or waiting for the dockerapi to come back.
//
// It replaces the shell's `kill -STOP`/`kill -CONT` on the background PIDs.
// Signalling a stopped process is a blunt instrument: a probe suspended
// mid-handshake leaves the peer holding a connection until it times out, and a
// SIGCONT delivered while the shell was between commands could be lost entirely.
// A gate the runners cooperate with pauses them at a defined point instead —
// between rounds, never mid-probe.
type Gate struct {
	mu   sync.Mutex
	open chan struct{}
}

// NewGate returns an open gate.
func NewGate() *Gate {
	g := &Gate{open: make(chan struct{})}
	close(g.open)
	return g
}

// Pause closes the gate. Runners already inside a round finish it; the next one
// blocks. Pausing an already-paused gate does nothing.
func (g *Gate) Pause() {
	g.mu.Lock()
	defer g.mu.Unlock()

	select {
	case <-g.open:
		g.open = make(chan struct{})
	default:
		// Already closed.
	}
}

// Resume opens the gate and releases every waiting runner.
func (g *Gate) Resume() {
	g.mu.Lock()
	defer g.mu.Unlock()

	select {
	case <-g.open:
		// Already open.
	default:
		close(g.open)
	}
}

// Paused reports the current state.
func (g *Gate) Paused() bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	select {
	case <-g.open:
		return false
	default:
		return true
	}
}

// Wait blocks until the gate is open or ctx is cancelled.
func (g *Gate) Wait(ctx context.Context) error {
	g.mu.Lock()
	open := g.open
	g.mu.Unlock()

	select {
	case <-open:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Clock is the supervisor's view of time. The real implementation is Realtime;
// tests substitute one that returns immediately, so a check whose interval is
// half a minute does not make the test suite take half a minute.
type Clock interface {
	Now() time.Time
	// Sleep waits for d or until ctx is cancelled, returning ctx.Err() in the
	// latter case.
	Sleep(ctx context.Context, d time.Duration) error
}

// Realtime is the production Clock.
type Realtime struct{}

// Now implements Clock.
func (Realtime) Now() time.Time { return time.Now() }

// Sleep implements Clock.
func (Realtime) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
