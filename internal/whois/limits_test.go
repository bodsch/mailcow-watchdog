package whois

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// TestLookupCapsTheAnswer is the one boundary in this service where the bytes
// come from a machine nobody here controls.
//
// The lookup enriches a ban notification, and the answer goes into the mail
// verbatim. A registry that is misconfigured, compromised, or simply chatty can
// send as much as it likes; without the cap the watchdog reads all of it into
// memory and mails it. The comment on the LimitReader says so — nothing checked
// that the reader was still there.
func TestLookupCapsTheAnswer(t *testing.T) {
	const cap = 64 << 10

	// A server that keeps writing until the client gives up. Not a large fixed
	// string: that would pass even if the cap were raised tenfold, and the point
	// is that the client stops on its own.
	addr := floodServer(t)

	client := New(Options{
		Root:    "whois.iana.org",
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
		},
	})

	done := make(chan string, 1)
	go func() {
		record, _ := client.Lookup(context.Background(), "192.0.2.1")
		done <- record
	}()

	select {
	case record := <-done:
		// Exactly the cap, not merely "not too much": the server sends without
		// end, so anything short of the cap would mean the read stopped for some
		// other reason and the test proves nothing about the limit.
		if len(record) != cap {
			t.Errorf("the answer is %d bytes, want exactly %d — an unbounded read "+
				"turns one ban notification into as much mail as the registry cares to send",
				len(record), cap)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the lookup never returned against a server that keeps writing; " +
			"the fail2ban notification would block and the ban would go unreported")
	}
}

// TestLookupGivesUpOnASilentServer: the referral means two servers are contacted
// in sequence, and either can accept the connection and then say nothing. The
// lookup runs inside the fail2ban event handler, so a lookup that never returns
// stops the watchdog from acting on any further event — bans stop being reported
// and no container gets restarted, while nothing in the log explains it.
func TestLookupGivesUpOnASilentServer(t *testing.T) {
	silent := silentServer(t)

	client := New(Options{
		Root:    "whois.iana.org",
		Timeout: 300 * time.Millisecond,
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", silent)
		},
	})

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := client.Lookup(context.Background(), "192.0.2.1")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("a server that never answered produced no error")
		}
		if took := time.Since(start); took > 3*time.Second {
			t.Errorf("the lookup took %v, want it bounded by the configured timeout", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup ignored its own timeout against a silent server")
	}
}

// TestDefaultTimeoutIsTheShellsPatience keeps the constant honest: watchdog.sh
// ran `whois` with a two-second budget, and a longer one here would hold up the
// ban notification the shell delivered promptly.
func TestDefaultTimeoutIsTheShellsPatience(t *testing.T) {
	if DefaultTimeout != 2*time.Second {
		t.Errorf("DefaultTimeout = %v, want 2s", DefaultTimeout)
	}
	if got := New(Options{}).timeout; got != DefaultTimeout {
		t.Errorf("an unset Timeout gives %v, want %v", got, DefaultTimeout)
	}
}

// floodServer writes until the client hangs up.
func floodServer(t *testing.T) string {
	t.Helper()
	return serve(t, func(conn net.Conn) {
		block := strings.Repeat("netname: FLOOD\n", 1024)
		for {
			if _, err := conn.Write([]byte(block)); err != nil {
				return
			}
		}
	})
}

// silentServer accepts and then says nothing, which is how a wedged registry
// behaves.
func silentServer(t *testing.T) string {
	t.Helper()

	done := make(chan struct{})
	addr := serve(t, func(net.Conn) { <-done })
	t.Cleanup(func() { close(done) })
	return addr
}

// serve runs handle for every connection until the test ends.
func serve(t *testing.T, handle func(net.Conn)) string {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handle(conn)
			}()
		}
	}()

	_ = errors.New("")
	return ln.Addr().String()
}
