package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// readLimit caps how much of a banner the expect matcher buffers. Every service
// probed here announces itself in well under a kilobyte; the limit exists so a
// misbehaving peer cannot make the watchdog allocate without bound.
const readLimit = 8 << 10

// TCPOptions configures a TCP probe, mirroring the check_tcp flags the shell
// script used.
type TCPOptions struct {
	// Send is written after the connection is established (check_tcp -s).
	Send string
	// Expect is a substring the server's response must contain (check_tcp -e).
	// When empty, a successful connection is enough.
	Expect string
	// Quit is written before closing, to let the peer shut down cleanly
	// (check_tcp -q).
	Quit string
	// TLS wraps the connection in a TLS handshake before anything is written.
	TLS bool
	// ServerName is sent as SNI. It only matters for services that select a
	// certificate by name; verification is off regardless.
	ServerName string
}

// TCP connects to a service and optionally exchanges a fixed line of protocol.
// It replaces check_tcp and, with the right defaults, check_clamd.
type TCP struct {
	name string
	addr Addr
	port int
	opts TCPOptions
}

// NewTCP returns a TCP probe against addr:port.
func NewTCP(name string, addr Addr, port int, opts TCPOptions) *TCP {
	return &TCP{name: name, addr: addr, port: port, opts: opts}
}

// NewClamd returns the clamd probe. Nagios ships check_clamd as check_tcp
// preconfigured with clamd's port and its PING/PONG exchange.
func NewClamd(name string, addr Addr) *TCP {
	return NewTCP(name, addr, 3310, TCPOptions{Send: "PING\n", Expect: "PONG"})
}

// Name implements Probe.
func (p *TCP) Name() string { return p.name }

// Run implements Probe.
func (p *TCP) Run(ctx context.Context) Result {
	host, bad := resolve(ctx, p.addr, p.name)
	if bad != nil {
		return *bad
	}

	conn, err := p.connect(ctx, host)
	if err != nil {
		return Critical("%s: cannot connect to %s:%d: %v", p.name, host, p.port, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if p.opts.Send != "" {
		if _, err := io.WriteString(conn, p.opts.Send); err != nil {
			return Critical("%s: cannot send to %s:%d: %v", p.name, host, p.port, err)
		}
	}

	if p.opts.Expect != "" {
		got, err := readUntil(conn, p.opts.Expect)
		if err != nil && !strings.Contains(got, p.opts.Expect) {
			return Critical("%s: reading from %s:%d failed: %v (got %q)",
				p.name, host, p.port, err, trim(got))
		}
		if !strings.Contains(got, p.opts.Expect) {
			return Critical("%s: %s:%d did not answer with %q, got %q",
				p.name, host, p.port, p.opts.Expect, trim(got))
		}
	}

	if p.opts.Quit != "" {
		_, _ = io.WriteString(conn, p.opts.Quit)
	}

	return OK("%s: %s:%d responded as expected", p.name, host, p.port)
}

// connect dials and, when configured, completes the TLS handshake.
func (p *TCP) connect(ctx context.Context, host string) (net.Conn, error) {
	conn, err := dial(ctx, host, p.port)
	if err != nil {
		return nil, err
	}
	if !p.opts.TLS {
		return conn, nil
	}

	name := p.opts.ServerName
	if name == "" {
		name = host
	}
	tlsConn := tls.Client(conn, tlsConfig(name))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		// The handshake error is the verdict; whether the socket closed cleanly
		// afterwards adds nothing.
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// readUntil reads until want appears, the peer closes, or the deadline expires.
// Services such as ManageSieve emit a multi-line banner, so a single Read is not
// enough to decide.
func readUntil(r io.Reader, want string) (string, error) {
	var buf bytes.Buffer
	chunk := make([]byte, 1024)

	for buf.Len() < readLimit {
		n, err := r.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			if strings.Contains(buf.String(), want) {
				return buf.String(), nil
			}
		}
		if err != nil {
			return buf.String(), err
		}
	}
	return buf.String(), nil
}

// trim shortens a banner for a log line and strips the line breaks that would
// otherwise wrap the message across several lines.
func trim(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " "))
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// Milter probes rspamd's proxy worker, which speaks the milter protocol and has
// no ping of its own.
//
// watchdog.sh phrased this as "curl the port and treat exit code 28 (timeout) as
// a failure": a live worker closes or answers the bogus HTTP request quickly,
// whereas a wedged one leaves the caller hanging. The Go version says the same
// thing directly — a read that neither yields bytes nor EOF within the timeout
// is the failure.
type Milter struct {
	name    string
	addr    Addr
	port    int
	timeout time.Duration
}

// NewMilter returns a milter liveness probe.
func NewMilter(name string, addr Addr, port int, timeout time.Duration) *Milter {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Milter{name: name, addr: addr, port: port, timeout: timeout}
}

// Name implements Probe.
func (p *Milter) Name() string { return p.name }

// Run implements Probe.
func (p *Milter) Run(ctx context.Context) Result {
	host, bad := resolve(ctx, p.addr, p.name)
	if bad != nil {
		return *bad
	}

	conn, err := dial(ctx, host, p.port)
	if err != nil {
		return Critical("%s: cannot connect to milter %s:%d: %v", p.name, host, p.port, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(p.timeout))
	_, _ = io.WriteString(conn, "GET / HTTP/1.0\r\n\r\n")

	buf := make([]byte, 512)
	switch _, err := conn.Read(buf); {
	case err == nil, errors.Is(err, io.EOF):
		return OK("%s: milter %s:%d answered", p.name, host, p.port)
	case isTimeout(err):
		return Critical("%s: milter %s:%d did not answer within %s", p.name, host, p.port, p.timeout)
	default:
		// A reset or similar still proves the worker is processing connections.
		return OK("%s: milter %s:%d closed the connection (%v)", p.name, host, p.port, err)
	}
}

// isTimeout distinguishes "the peer is wedged" from "the peer hung up", which is
// the whole point of the milter probe.
func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
