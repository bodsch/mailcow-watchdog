package probe

import (
	"strings"
	"testing"

	"bodsch.me/mailcow-watchdog/internal/health"
)

// postfixTransaction is the conversation watchdog.sh scripted for postfix on
// port 589: check_smtp -f watchdog@invalid -C "RCPT TO:watchdog@localhost"
// -C DATA -C . -R 250.
func postfixTransaction() SMTPOptions {
	return SMTPOptions{
		HELO: "mail.example.org",
		From: "watchdog@invalid",
		Commands: []Command{
			{Send: "RCPT TO:watchdog@localhost", Expect: "250"},
			{Send: "DATA"},
			{Send: "."},
		},
	}
}

func TestSMTPTransaction(t *testing.T) {
	host, port := scriptedServer(t, "220 mail.example.org ESMTP Postfix\r\n", []step{
		{Expect: "EHLO", Reply: "250-mail.example.org\r\n250 PIPELINING\r\n"},
		{Expect: "MAIL FROM", Reply: "250 2.1.0 Ok\r\n"},
		{Expect: "RCPT TO", Reply: "250 2.1.5 Ok\r\n"},
		{Expect: "DATA", Reply: "354 End data with <CR><LF>.<CR><LF>\r\n"},
		{Expect: ".", Reply: "250 2.0.0 Ok: queued\r\n"},
		{Expect: "QUIT", Reply: "221 2.0.0 Bye\r\n"},
	})

	res := runProbe(t, NewSMTP("postfix", Static(host), port, postfixTransaction()))
	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
}

// A multi-line EHLO reply is the norm; the reader has to join the continuation
// lines or the next command reads a stale one.
func TestSMTPHandlesMultilineGreeting(t *testing.T) {
	host, port := scriptedServer(t, "220 ready\r\n", []step{
		{Expect: "EHLO", Reply: "250-mail.example.org\r\n250-PIPELINING\r\n250-SIZE\r\n250 STARTTLS\r\n"},
		{Expect: "MAIL FROM", Reply: "250 Ok\r\n"},
		{Expect: "RCPT TO", Reply: "250 Ok\r\n"},
		{Expect: "DATA", Reply: "354 go\r\n"},
		{Expect: ".", Reply: "250 queued\r\n"},
		{Expect: "QUIT", Reply: "221 bye\r\n"},
	})

	if res := runProbe(t, NewSMTP("postfix", Static(host), port, postfixTransaction())); res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
}

func TestSMTPFallsBackToHELO(t *testing.T) {
	host, port := scriptedServer(t, "220 ready\r\n", []step{
		{Expect: "EHLO", Reply: "500 command not recognized\r\n"},
		{Expect: "HELO", Reply: "250 mail.example.org\r\n"},
		{Expect: "QUIT", Reply: "221 bye\r\n"},
	})

	res := runProbe(t, NewSMTP("postfix", Static(host), port, SMTPOptions{HELO: "mail.example.org"}))
	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
}

func TestSMTPBadGreetingIsCritical(t *testing.T) {
	host, port := bannerServer(t, "554 no service here\r\n")

	res := runProbe(t, NewSMTP("postfix", Static(host), port, postfixTransaction()))
	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "want 220") {
		t.Errorf("message = %q, want it to name the expected greeting", res.Message)
	}
}

// Nagios graded a MAIL FROM that was not accepted as a warning rather than a
// hard failure, so it costs one error point instead of two.
func TestSMTPRejectedSenderIsWarning(t *testing.T) {
	host, port := scriptedServer(t, "220 ready\r\n", []step{
		{Expect: "EHLO", Reply: "250 ok\r\n"},
		{Expect: "MAIL FROM", Reply: "550 5.1.8 sender rejected\r\n"},
	})

	res := runProbe(t, NewSMTP("postfix", Static(host), port, postfixTransaction()))
	if res.Status != health.StatusWarning {
		t.Errorf("status = %v (%s), want WARNING", res.Status, res.Message)
	}
	if res.Weight() != 1 {
		t.Errorf("Weight() = %d, want 1", res.Weight())
	}
}

func TestSMTPUnexpectedCommandReplyIsWarning(t *testing.T) {
	host, port := scriptedServer(t, "220 ready\r\n", []step{
		{Expect: "EHLO", Reply: "250 ok\r\n"},
		{Expect: "MAIL FROM", Reply: "250 ok\r\n"},
		{Expect: "RCPT TO", Reply: "451 4.3.0 try again later\r\n"},
	})

	res := runProbe(t, NewSMTP("postfix", Static(host), port, postfixTransaction()))
	if res.Status != health.StatusWarning {
		t.Errorf("status = %v (%s), want WARNING", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, `want it to contain "250"`) {
		t.Errorf("message = %q, want it to name the expectation", res.Message)
	}
}

// Dovecot's delivery port speaks LMTP, and the probe deliberately expects a
// rejection: only a working user lookup can say "User doesn't exist".
func TestLMTPExpectsRecipientRejection(t *testing.T) {
	opts := SMTPOptions{
		LMTP: true,
		HELO: "mail.example.org",
		From: "watchdog@invalid",
		Commands: []Command{
			{Send: "RCPT TO:<watchdog@invalid>", Expect: "User doesn't exist"},
		},
	}

	host, port := scriptedServer(t, "220 dovecot.example.org Dovecot ready\r\n", []step{
		{Expect: "LHLO", Reply: "250-dovecot\r\n250 PIPELINING\r\n"},
		{Expect: "MAIL FROM", Reply: "250 2.1.0 OK\r\n"},
		{Expect: "RCPT TO", Reply: "550 5.1.1 <watchdog@invalid> User doesn't exist\r\n"},
		{Expect: "QUIT", Reply: "221 bye\r\n"},
	})

	if res := runProbe(t, NewSMTP("dovecot-lmtp", Static(host), port, opts)); res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
}

// An LMTP server must not be offered a fallback to HELO.
func TestLMTPRejectedLHLOIsCritical(t *testing.T) {
	host, port := scriptedServer(t, "220 ready\r\n", []step{
		{Expect: "LHLO", Reply: "500 unknown command\r\n"},
	})

	res := runProbe(t, NewSMTP("dovecot-lmtp", Static(host), port,
		SMTPOptions{LMTP: true, HELO: "mail.example.org"}))
	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "LHLO") {
		t.Errorf("message = %q, want it to name LHLO", res.Message)
	}
}

func TestSMTPRefusedStartTLSIsCritical(t *testing.T) {
	host, port := scriptedServer(t, "220 ready\r\n", []step{
		{Expect: "EHLO", Reply: "250 ok\r\n"},
		{Expect: "STARTTLS", Reply: "454 4.7.0 TLS not available\r\n"},
	})

	res := runProbe(t, NewSMTP("postfix-tls", Static(host), port,
		SMTPOptions{HELO: "mail.example.org", StartTLS: true}))
	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "refused STARTTLS") {
		t.Errorf("message = %q, want it to name STARTTLS", res.Message)
	}
}

func TestSMTPConnectionRefusedIsCritical(t *testing.T) {
	host, port := closedPort(t)

	res := runProbe(t, NewSMTP("postfix", Static(host), port, postfixTransaction()))
	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
}

func TestNewSMTPDefaultsHELO(t *testing.T) {
	p := NewSMTP("postfix", Static("x"), 25, SMTPOptions{})
	if p.opts.HELO != "localhost" {
		t.Errorf("HELO = %q, want localhost", p.opts.HELO)
	}
}
