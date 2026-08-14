package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/smtp"
	"sort"
	"strings"
	"time"
)

// SMTPPort is where a receiving MX listens.
const SMTPPort = 25

// smtpTimeout bounds one delivery attempt. watchdog.sh wrapped smtp-cli in
// `timeout 10s`.
const smtpTimeout = 10 * time.Second

// MXLookup returns a domain's mail exchangers, most preferred first.
type MXLookup func(ctx context.Context, domain string) ([]string, error)

// DefaultMXLookup resolves through the container's resolver, which in mailcow is
// unbound.
func DefaultMXLookup(ctx context.Context, domain string) ([]string, error) {
	records, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].Pref < records[j].Pref })

	hosts := make([]string, 0, len(records))
	for _, record := range records {
		hosts = append(hosts, strings.TrimSuffix(record.Host, "."))
	}
	return hosts, nil
}

// DialFunc opens a connection to an MX.
type DialFunc func(ctx context.Context, addr string) (net.Conn, error)

// SMTPSender delivers mail directly to each recipient's MX.
//
// This is what smtp-cli did when it was called without a --server: it looked the
// recipient domain's MX up and spoke SMTP to it. There is no MTA inside the
// watchdog container to relay through, which is why watchdog.sh checked for an
// MX first and skipped the notification when there was none.
type SMTPSender struct {
	from       string
	helo       string
	recipients []string
	port       int
	lookupMX   MXLookup
	dial       DialFunc
	now        func() time.Time
	log        *slog.Logger
}

// SMTPOptions configures the sender.
type SMTPOptions struct {
	// From is the envelope sender, watchdog@<MAILCOW_HOSTNAME>.
	From string
	// HELO is announced to the receiving MX; mailcow uses MAILCOW_HOSTNAME so
	// the greeting matches the sender's domain.
	HELO string
	// Recipients is WATCHDOG_NOTIFY_EMAIL.
	Recipients []string
	// Port defaults to 25.
	Port int
	// LookupMX defaults to DefaultMXLookup.
	LookupMX MXLookup
	// Dial defaults to an IPv4 dialer. Every smtp-cli call passed --ipv4.
	Dial DialFunc
	// Now defaults to time.Now and stamps the Date header.
	Now func() time.Time
}

// NewSMTP returns a mail notifier, or nil when no recipients are configured.
func NewSMTP(opts SMTPOptions, log *slog.Logger) *SMTPSender {
	if len(opts.Recipients) == 0 {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	if opts.Port == 0 {
		opts.Port = SMTPPort
	}
	if opts.LookupMX == nil {
		opts.LookupMX = DefaultMXLookup
	}
	if opts.Dial == nil {
		opts.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: smtpTimeout}
			return d.DialContext(ctx, "tcp4", addr)
		}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	return &SMTPSender{
		from:       opts.From,
		helo:       opts.HELO,
		recipients: opts.Recipients,
		port:       opts.Port,
		lookupMX:   opts.LookupMX,
		dial:       opts.Dial,
		now:        opts.Now,
		log:        log.With("component", "notify.smtp"),
	}
}

// Send implements Notifier. Each recipient is delivered to independently, so one
// unreachable domain does not stop the others.
func (s *SMTPSender) Send(ctx context.Context, msg Message) error {
	var errs []error

	for _, rcpt := range s.recipients {
		if err := s.deliver(ctx, rcpt, msg); err != nil {
			s.log.Error("cannot deliver notification", "err", err, "rcpt", rcpt)
			errs = append(errs, fmt.Errorf("delivering to %s: %w", rcpt, err))
			continue
		}
		s.log.Info("sent notification email", "rcpt", rcpt, "service", msg.Service)
	}
	return errors.Join(errs...)
}

func (s *SMTPSender) deliver(ctx context.Context, rcpt string, msg Message) error {
	at := strings.LastIndex(rcpt, "@")
	if at < 0 {
		return fmt.Errorf("%q is not an address", rcpt)
	}
	domain := rcpt[at+1:]

	hosts, err := s.lookupMX(ctx, domain)
	if err != nil {
		return fmt.Errorf("looking up the MX for %s: %w", domain, err)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("%s has no MX record", domain)
	}

	body := s.compose(rcpt, msg)

	// Try the exchangers in preference order, as any MTA would.
	var attempts []error
	for _, host := range hosts {
		err := s.deliverTo(ctx, host, rcpt, body)
		if err == nil {
			return nil
		}
		attempts = append(attempts, fmt.Errorf("%s: %w", host, err))
	}
	return errors.Join(attempts...)
}

// deliverTo runs one SMTP transaction against one exchanger.
func (s *SMTPSender) deliverTo(ctx context.Context, host, rcpt string, body []byte) error {
	dialCtx, cancel := context.WithTimeout(ctx, smtpTimeout)
	defer cancel()

	conn, err := s.dial(dialCtx, net.JoinHostPort(host, fmt.Sprint(s.port)))
	if err != nil {
		return err
	}
	defer conn.Close()

	// The deadline is wall-clock time as the kernel sees it, so it comes from
	// time.Now rather than from s.now: the injectable clock stamps the Date header
	// and is pinned to a fixed instant in tests, which would put the deadline in
	// the past and fail every transaction.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(smtpTimeout))
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("starting the SMTP session: %w", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Hello(s.helo); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}

	// Encryption is opportunistic: the alert has to get through even to an
	// exchanger that offers no TLS, and the certificate cannot be verified
	// against a name we only learned from DNS.
	if ok, _ := client.Extension("STARTTLS"); ok {
		//nolint:gosec // G402: opportunistic TLS to an arbitrary MX; failing the
		// handshake would mean losing the alert entirely.
		if err := client.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: true}); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}

	if err := client.Mail(s.from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := client.Rcpt(rcpt); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("writing the message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finishing the message: %w", err)
	}

	return client.Quit()
}

// compose renders the message. The headers mirror the smtp-cli invocation:
// UTF-8, plain text and the high priority flag the shell always set.
func (s *SMTPSender) compose(rcpt string, msg Message) []byte {
	var b strings.Builder

	fmt.Fprintf(&b, "Date: %s\r\n", s.now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "From: %s\r\n", s.from)
	fmt.Fprintf(&b, "To: %s\r\n", rcpt)
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeHeader(msg.Subject))
	fmt.Fprintf(&b, "Message-ID: <%d.%s>\r\n", s.now().UnixNano(), s.from)
	b.WriteString("X-Priority: 1\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(normaliseNewlines(msg.Body))

	return []byte(b.String())
}

// encodeHeader applies RFC 2047 encoding when the subject is not plain ASCII,
// so that a German umlaut in an alert does not arrive as mojibake.
func encodeHeader(value string) string {
	for i := 0; i < len(value); i++ {
		if value[i] > 127 {
			return mime.QEncoding.Encode("UTF-8", value)
		}
	}
	return value
}

// normaliseNewlines converts the body to the CRLF line endings SMTP requires.
//
// Dot-stuffing is deliberately not done here: the writer returned by
// smtp.Client.Data is a textproto dot-writer, which already escapes a line
// consisting of a leading dot. Doing it twice would put a stray dot in the body
// of every alert whose transcript happens to start a line with one.
func normaliseNewlines(body string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\n", "\r\n")

	if !strings.HasSuffix(body, "\r\n") {
		body += "\r\n"
	}
	return body
}
