package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

// Command is one scripted step of an SMTP conversation, mirroring a check_smtp
// -C/-R pair. An empty Expect means the response is recorded but not graded,
// which is what Nagios did for a -C without a matching -R.
type Command struct {
	Send   string
	Expect string
}

// SMTPOptions configures an SMTP or LMTP probe.
type SMTPOptions struct {
	// LMTP switches the greeting to LHLO. Dovecot's delivery port speaks LMTP
	// (check_smtp -L).
	LMTP bool
	// HELO is the name announced to the peer. It defaults to "localhost" the way
	// the Nagios plugin did when no FQDN was configured.
	HELO string
	// From, when set, triggers a MAIL FROM command (check_smtp -f).
	From string
	// Commands are executed in order after MAIL FROM (check_smtp -C).
	Commands []Command
	// StartTLS upgrades the connection before the scripted commands run
	// (check_smtp -S).
	StartTLS bool
	// MinCertDays turns the probe into a certificate expiry check: the
	// conversation stops right after the handshake (check_smtp -D).
	MinCertDays int
}

// SMTP replaces check_smtp. It covers four distinct uses in the original
// watchdog: the postfix mail transaction, the postfix STARTTLS handshake, the
// dovecot LMTP recipient lookup and the certificate expiry check.
type SMTP struct {
	name string
	addr Addr
	port int
	opts SMTPOptions
}

// NewSMTP returns an SMTP probe against addr:port.
func NewSMTP(name string, addr Addr, port int, opts SMTPOptions) *SMTP {
	if opts.HELO == "" {
		opts.HELO = "localhost"
	}
	return &SMTP{name: name, addr: addr, port: port, opts: opts}
}

// Name implements Probe.
func (p *SMTP) Name() string { return p.name }

// Run implements Probe.
//
// Connection and protocol failures are CRITICAL; a response that does not match
// its expectation is a WARNING, which is how the Nagios plugin graded the same
// two situations.
func (p *SMTP) Run(ctx context.Context) Result {
	host, bad := resolve(ctx, p.addr, p.name)
	if bad != nil {
		return *bad
	}

	conn, err := dial(ctx, host, p.port)
	if err != nil {
		return Critical("%s: cannot connect to %s:%d: %v", p.name, host, p.port, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	s := &smtpSession{conn: conn, text: textproto.NewConn(conn)}
	where := fmt.Sprintf("%s:%d", host, p.port)

	// The greeting must be a 220, or we are not talking to an MTA at all.
	if code, line, err := s.read(); err != nil {
		return Critical("%s: %s sent no greeting: %v", p.name, where, err)
	} else if code != 220 {
		return Critical("%s: %s greeted with %q, want 220", p.name, where, trim(line))
	}

	if res, ok := p.greet(s, where); !ok {
		return res
	}

	if p.opts.StartTLS {
		state, res, ok := p.startTLS(ctx, s, host, where)
		if !ok {
			return res
		}
		if p.opts.MinCertDays > 0 {
			// A certificate check has nothing to say about mail flow, so the
			// conversation ends here.
			_ = s.write("QUIT")
			return certExpiry(state, p.opts.MinCertDays, fmt.Sprintf("%s: %s", p.name, where))
		}
	}

	if res, ok := p.mailFrom(s, where); !ok {
		return res
	}
	if res, ok := p.runCommands(s, where); !ok {
		return res
	}

	_ = s.write("QUIT")
	return OK("%s: %s completed the %s conversation", p.name, where, p.protocol())
}

// greet sends EHLO/LHLO and, for SMTP only, falls back to HELO for servers that
// predate ESMTP.
func (p *SMTP) greet(s *smtpSession, where string) (Result, bool) {
	verb := "EHLO"
	if p.opts.LMTP {
		verb = "LHLO"
	}

	code, line, err := s.cmd("%s %s", verb, p.opts.HELO)
	if err != nil {
		return Critical("%s: %s did not answer %s: %v", p.name, where, verb, err), false
	}
	if code == 250 {
		return Result{}, true
	}
	if p.opts.LMTP {
		return Critical("%s: %s rejected LHLO: %q", p.name, where, trim(line)), false
	}

	code, line, err = s.cmd("HELO %s", p.opts.HELO)
	if err != nil {
		return Critical("%s: %s did not answer HELO: %v", p.name, where, err), false
	}
	if code != 250 {
		return Critical("%s: %s rejected HELO: %q", p.name, where, trim(line)), false
	}
	return Result{}, true
}

// startTLS performs the upgrade and returns the negotiated connection state so
// the caller can inspect the certificate.
func (p *SMTP) startTLS(ctx context.Context, s *smtpSession, host, where string) (tls.ConnectionState, Result, bool) {
	var zero tls.ConnectionState

	code, line, err := s.cmd("STARTTLS")
	if err != nil {
		return zero, Critical("%s: %s did not answer STARTTLS: %v", p.name, where, err), false
	}
	if code != 220 {
		return zero, Critical("%s: %s refused STARTTLS: %q", p.name, where, trim(line)), false
	}

	tlsConn := tls.Client(s.conn, tlsConfig(host))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return zero, Critical("%s: TLS handshake with %s failed: %v", p.name, where, err), false
	}

	// Everything after STARTTLS runs over the encrypted connection, and the
	// protocol requires the greeting to be repeated.
	s.conn = tlsConn
	s.text = textproto.NewConn(tlsConn)
	if res, ok := p.greet(s, where); !ok {
		return zero, res, false
	}

	return tlsConn.ConnectionState(), Result{}, true
}

// mailFrom sends the envelope sender when one is configured. Nagios graded a
// non-250 reply here as a warning rather than a hard failure.
func (p *SMTP) mailFrom(s *smtpSession, where string) (Result, bool) {
	if p.opts.From == "" {
		return Result{}, true
	}
	code, line, err := s.cmd("MAIL FROM:<%s>", p.opts.From)
	if err != nil {
		return Critical("%s: %s did not answer MAIL FROM: %v", p.name, where, err), false
	}
	if code != 250 {
		return Warning("%s: %s answered MAIL FROM with %q, want 250", p.name, where, trim(line)), false
	}
	return Result{}, true
}

// runCommands walks the scripted conversation. A command whose Expect is empty
// is sent and its reply recorded but not graded.
func (p *SMTP) runCommands(s *smtpSession, where string) (Result, bool) {
	for _, c := range p.opts.Commands {
		code, line, err := s.cmd("%s", c.Send)
		if err != nil {
			return Critical("%s: %s did not answer %q: %v", p.name, where, c.Send, err), false
		}
		if c.Expect == "" {
			continue
		}
		full := fmt.Sprintf("%d %s", code, line)
		if !strings.Contains(full, c.Expect) {
			return Warning("%s: %s answered %q with %q, want it to contain %q",
				p.name, where, c.Send, trim(full), c.Expect), false
		}
	}
	return Result{}, true
}

func (p *SMTP) protocol() string {
	if p.opts.LMTP {
		return "LMTP"
	}
	return "SMTP"
}

// smtpSession wraps the line protocol shared by SMTP and LMTP. The connection is
// swapped out in place when STARTTLS upgrades it.
type smtpSession struct {
	conn net.Conn
	text *textproto.Conn
}

// cmd sends one command and reads the reply.
func (s *smtpSession) cmd(format string, args ...any) (int, string, error) {
	if err := s.write(fmt.Sprintf(format, args...)); err != nil {
		return 0, "", err
	}
	return s.read()
}

func (s *smtpSession) write(line string) error {
	return s.text.PrintfLine("%s", line)
}

// read consumes a reply, joining the continuation lines of a multi-line
// response. The expect code is zero so that the caller, not textproto, decides
// what an acceptable reply is.
func (s *smtpSession) read() (int, string, error) {
	return s.text.ReadResponse(0)
}
