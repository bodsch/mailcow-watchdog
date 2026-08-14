package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
)

// IMAPOptions configures an IMAP probe.
type IMAPOptions struct {
	// TLS connects with implicit TLS, as on port 993 (check_imap -S).
	TLS bool
	// Expect is the substring the greeting must contain (check_imap -e). It
	// defaults to Nagios' own "* OK".
	Expect string
	// MinCertDays turns the probe into a certificate expiry check (check_imap
	// -D). It requires TLS.
	MinCertDays int
}

// IMAP replaces check_imap: it connects, reads the greeting and logs out again.
// Dovecot is probed on 143 and 993, and the certificate check reuses the 993
// handshake.
type IMAP struct {
	name string
	addr Addr
	port int
	opts IMAPOptions
}

// NewIMAP returns an IMAP probe against addr:port.
func NewIMAP(name string, addr Addr, port int, opts IMAPOptions) *IMAP {
	if opts.Expect == "" {
		opts.Expect = "* OK"
	}
	return &IMAP{name: name, addr: addr, port: port, opts: opts}
}

// Name implements Probe.
func (p *IMAP) Name() string { return p.name }

// Run implements Probe.
func (p *IMAP) Run(ctx context.Context) Result {
	host, bad := resolve(ctx, p.addr, p.name)
	if bad != nil {
		return *bad
	}
	where := fmt.Sprintf("%s:%d", host, p.port)

	conn, err := dial(ctx, host, p.port)
	if err != nil {
		return Critical("%s: cannot connect to %s: %v", p.name, where, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	rw := io.ReadWriter(conn)
	var state tls.ConnectionState
	if p.opts.TLS {
		tlsConn := tls.Client(conn, tlsConfig(host))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return Critical("%s: TLS handshake with %s failed: %v", p.name, where, err)
		}
		state = tlsConn.ConnectionState()
		rw = tlsConn
	}

	if p.opts.MinCertDays > 0 {
		if !p.opts.TLS {
			return Unknown("%s: certificate check needs an implicit TLS connection", p.name)
		}
		// The greeting is irrelevant to certificate validity, so the probe stops
		// after the handshake.
		return certExpiry(state, p.opts.MinCertDays, fmt.Sprintf("%s: %s", p.name, where))
	}

	greeting, err := readUntil(rw, p.opts.Expect)
	if err != nil && !strings.Contains(greeting, p.opts.Expect) {
		return Critical("%s: reading the greeting from %s failed: %v (got %q)",
			p.name, where, err, trim(greeting))
	}
	if !strings.Contains(greeting, p.opts.Expect) {
		return Critical("%s: %s greeted with %q, want it to contain %q",
			p.name, where, trim(greeting), p.opts.Expect)
	}

	// Nagios' check_imap ends the session politely; dovecot logs an aborted
	// connection otherwise, which would be noise in the mail log every round.
	_, _ = io.WriteString(rw, "a1 LOGOUT\r\n")

	return OK("%s: %s greeted with %q", p.name, where, trim(greeting))
}
