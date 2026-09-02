package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestEveryProbeHonoursItsDeadline is the timeout contract, and until now only
// the milter probe was held to it.
//
// A probe that ignores the deadline blocks the check's goroutine on a socket that
// will never answer. That check then never runs another round — no verdict, no
// error, no metric, nothing in the log. The service it watches is unmonitored and
// the watchdog reports itself healthy, which is the worst of the failure modes it
// has: an outage in exactly the service whose wedged worker caused it would go
// unnoticed indefinitely.
//
// The server here accepts the connection and then says nothing, which is how a
// wedged Dovecot or php-fpm worker behaves — the case the watchdog exists for.
func TestEveryProbeHonoursItsDeadline(t *testing.T) {
	host, port := deadServer(t)
	silentDNS := silentUDPServer(t)

	probes := []Probe{
		NewTCP("tcp", Static(host), port, TCPOptions{}),
		NewTCP("tcp-expect", Static(host), port, TCPOptions{Send: "PING\n", Expect: "PONG"}),
		NewSMTP("smtp", Static(host), port, SMTPOptions{HELO: "mail.example.org"}),
		NewSMTP("smtp-starttls", Static(host), port, SMTPOptions{HELO: "mail.example.org", StartTLS: true}),
		NewIMAP("imap", Static(host), port, IMAPOptions{}),
		NewIMAP("imaps", Static(host), port, IMAPOptions{TLS: true}),
		NewHTTP("http", Static(host), port, "/"),
		NewMilter("milter", Static(host), port, 200*time.Millisecond),
		NewDNS("dns", Static(silentDNS.host), silentDNS.port, "example.org"),
		NewDNSSEC("dnssec", Static(silentDNS.host), silentDNS.port, "org"),
	}

	for _, p := range probes {
		t.Run(p.Name(), func(t *testing.T) {
			// A deadline far shorter than DefaultTimeout, so the suite does not
			// pay ten seconds per probe. Run takes the earlier of the two, which
			// is the same code path the ten-second bound goes through.
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()

			done := make(chan Result, 1)
			go func() { done <- Run(ctx, p) }()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s ignored the deadline against a server that accepts and stays silent; "+
					"in production this check would stop running rounds for good "+
					"and nothing would report it", p.Name())
			}
		})
	}
}

// TestRunAppliesTheDefaultTimeout is the other half: the supervisor hands the
// probes a context with no deadline of its own, so DefaultTimeout is what bounds
// every round in production. The test above proves the probes honour a deadline;
// this proves there is one to honour.
func TestRunAppliesTheDefaultTimeout(t *testing.T) {
	var seen time.Duration
	p := &stubProbe{name: "deadline", fn: func() Result { return OK("ok") }}
	p.observe = func(ctx context.Context) {
		if deadline, ok := ctx.Deadline(); ok {
			seen = time.Until(deadline)
		}
	}

	Run(context.Background(), p)

	if seen == 0 {
		t.Fatal("Run gave the probe a context with no deadline; a wedged service would block the check for ever")
	}
	// Generous either way: the point is that it is DefaultTimeout and not, say,
	// a minute inherited from somewhere else.
	if seen > DefaultTimeout || seen < DefaultTimeout-time.Second {
		t.Errorf("the probe saw %v left, want about %v", seen, DefaultTimeout)
	}
}

// silentUDPServer answers nothing, which is what a wedged unbound looks like to
// a resolver. A TCP server would not do: the DNS probe asks over UDP first and
// would get "connection refused" instead of silence, which is a different code
// path and returns immediately.
type udpTarget struct {
	host string
	port int
}

func silentUDPServer(t *testing.T) udpTarget {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("opening a UDP socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected address type %T", conn.LocalAddr())
	}
	return udpTarget{host: "127.0.0.1", port: addr.Port}
}
