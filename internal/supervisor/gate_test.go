package supervisor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestGateStartsOpen(t *testing.T) {
	g := NewGate()

	if g.Paused() {
		t.Error("a new gate should be open")
	}
	if err := g.Wait(context.Background()); err != nil {
		t.Errorf("Wait on an open gate = %v, want nil", err)
	}
}

func TestGatePauseBlocksUntilResume(t *testing.T) {
	g := NewGate()
	g.Pause()

	if !g.Paused() {
		t.Error("Paused() = false after Pause()")
	}

	released := make(chan error, 1)
	go func() { released <- g.Wait(context.Background()) }()

	select {
	case <-released:
		t.Fatal("Wait returned while the gate was closed")
	case <-time.After(50 * time.Millisecond):
	}

	g.Resume()
	select {
	case err := <-released:
		if err != nil {
			t.Errorf("Wait = %v, want nil after Resume", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Resume did not release the waiter")
	}
}

// A closed gate must not strand its waiters when the process is shutting down.
func TestGateWaitHonoursContextCancellation(t *testing.T) {
	g := NewGate()
	g.Pause()

	ctx, cancel := context.WithCancel(context.Background())
	released := make(chan error, 1)
	go func() { released <- g.Wait(ctx) }()

	cancel()
	select {
	case err := <-released:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Wait = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait ignored the cancelled context")
	}
}

// The supervisor pauses on every restart and on every dockerapi outage, so both
// operations have to tolerate being applied twice.
func TestGatePauseAndResumeAreIdempotent(t *testing.T) {
	g := NewGate()

	g.Pause()
	g.Pause()
	if !g.Paused() {
		t.Error("Paused() = false after two Pause() calls")
	}

	g.Resume()
	g.Resume()
	if g.Paused() {
		t.Error("Paused() = true after two Resume() calls")
	}
	if err := g.Wait(context.Background()); err != nil {
		t.Errorf("Wait = %v, want nil", err)
	}
}

// Every runner waits on the same gate, so one Resume has to release all of them.
func TestGateReleasesEveryWaiter(t *testing.T) {
	g := NewGate()
	g.Pause()

	const waiters = 20
	var wg sync.WaitGroup
	wg.Add(waiters)

	for i := 0; i < waiters; i++ {
		go func() {
			defer wg.Done()
			_ = g.Wait(context.Background())
		}()
	}

	// Give the goroutines a moment to reach the gate.
	time.Sleep(20 * time.Millisecond)
	g.Resume()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("not every waiter was released")
	}
}

func TestRealtimeSleep(t *testing.T) {
	clock := Realtime{}

	start := clock.Now()
	if err := clock.Sleep(context.Background(), 20*time.Millisecond); err != nil {
		t.Fatalf("Sleep: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
		t.Errorf("Sleep returned after %v, want at least 20ms", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := clock.Sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("Sleep on a cancelled context = %v, want context.Canceled", err)
	}
}
