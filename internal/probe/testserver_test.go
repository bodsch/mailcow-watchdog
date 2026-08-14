package probe

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
)

// listenLocal starts a loopback listener and serves every connection with
// handle until the test finishes. It returns the host and port the probes should
// be pointed at.
//
// The listener binds 127.0.0.1 explicitly because the probes dial "tcp4", the
// way every Nagios invocation in watchdog.sh passed -4.
func listenLocal(t *testing.T, handle func(conn net.Conn)) (host string, port int) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				handle(conn)
			}()
		}
	}()

	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// bannerServer answers every connection with a fixed banner and hangs up.
// Closing straight away keeps the probes from waiting out their full timeout
// when the banner is not the one they expect.
func bannerServer(t *testing.T, banner string) (string, int) {
	t.Helper()
	return listenLocal(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte(banner))
	})
}

// deadServer accepts connections and then does nothing at all, which is how a
// wedged worker behaves.
//
// The channel is closed in a cleanup registered after listenLocal's, so that
// LIFO ordering releases the blocked handlers before listenLocal waits for them.
func deadServer(t *testing.T) (string, int) {
	t.Helper()

	done := make(chan struct{})
	host, port := listenLocal(t, func(net.Conn) { <-done })
	t.Cleanup(func() { close(done) })

	return host, port
}

// closedPort returns an address nothing is listening on.
func closedPort(t *testing.T) (string, int) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return "127.0.0.1", port
}

// step is one scripted step of a line based conversation: the server waits
// for a command containing Expect and answers with Reply.
type step struct {
	Expect string
	Reply  string
}

// scriptedServer greets with banner and then walks through steps, answering each
// client line in turn. A step whose Expect does not match still gets its reply,
// so that a probe under test sees the protocol error rather than a hang.
func scriptedServer(t *testing.T, banner string, steps []step) (string, int) {
	t.Helper()

	return listenLocal(t, func(conn net.Conn) {
		if banner != "" {
			_, _ = conn.Write([]byte(banner))
		}
		r := bufio.NewReader(conn)
		for _, step := range steps {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if step.Expect != "" && !strings.Contains(line, step.Expect) {
				_, _ = conn.Write([]byte("502 unexpected " + strings.TrimSpace(line) + "\r\n"))
				continue
			}
			_, _ = conn.Write([]byte(step.Reply))
		}
	})
}

// runProbe executes p through Run with a background context, which is what the
// check runners do.
func runProbe(t *testing.T, p Probe) Result {
	t.Helper()
	return Run(context.Background(), p)
}
