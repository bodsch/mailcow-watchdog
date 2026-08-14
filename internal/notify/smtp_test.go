package notify

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMX is a minimal receiving mail exchanger. It records the transaction so a
// test can assert on the envelope and the message that arrived.
type fakeMX struct {
	mu sync.Mutex

	addr string

	From string
	To   []string
	Data string
	HELO string

	// reject, when set, makes the server refuse the named command.
	reject string
}

func startFakeMX(t *testing.T, reject string) *fakeMX {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	mx := &fakeMX{addr: ln.Addr().String(), reject: reject}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go mx.serve(conn)
		}
	}()
	return mx
}

func (m *fakeMX) serve(conn net.Conn) {
	defer conn.Close()

	_, _ = conn.Write([]byte("220 mx.example.org ESMTP\r\n"))
	r := bufio.NewReader(conn)

	inData := false
	var data strings.Builder

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}

		if inData {
			if strings.TrimRight(line, "\r\n") == "." {
				inData = false
				m.record(func() { m.Data = data.String() })
				_, _ = conn.Write([]byte("250 queued\r\n"))
				continue
			}
			data.WriteString(line)
			continue
		}

		verb := strings.ToUpper(strings.Fields(strings.TrimSpace(line) + " ")[0])
		if m.reject == verb {
			_, _ = conn.Write([]byte("550 rejected\r\n"))
			continue
		}

		switch verb {
		case "EHLO":
			m.record(func() { m.HELO = strings.TrimSpace(strings.TrimPrefix(line, "EHLO ")) })
			// No STARTTLS is advertised, so delivery stays in the clear —
			// exactly what happens with an exchanger that offers none.
			_, _ = conn.Write([]byte("250-mx.example.org\r\n250 SIZE 10240000\r\n"))
		case "HELO":
			_, _ = conn.Write([]byte("250 mx.example.org\r\n"))
		case "MAIL":
			m.record(func() { m.From = between(line, "<", ">") })
			_, _ = conn.Write([]byte("250 ok\r\n"))
		case "RCPT":
			m.record(func() { m.To = append(m.To, between(line, "<", ">")) })
			_, _ = conn.Write([]byte("250 ok\r\n"))
		case "DATA":
			inData = true
			_, _ = conn.Write([]byte("354 go ahead\r\n"))
		case "QUIT":
			_, _ = conn.Write([]byte("221 bye\r\n"))
			return
		default:
			_, _ = conn.Write([]byte("250 ok\r\n"))
		}
	}
}

func (m *fakeMX) record(f func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f()
}

func (m *fakeMX) snapshot() fakeMX {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fakeMX{From: m.From, To: append([]string(nil), m.To...), Data: m.Data, HELO: m.HELO}
}

func between(s, open, close string) string {
	i := strings.Index(s, open)
	j := strings.LastIndex(s, close)
	if i < 0 || j < 0 || j <= i {
		return ""
	}
	return s[i+len(open) : j]
}

// senderTo builds a sender that resolves every domain to the fake exchangers.
func senderTo(t *testing.T, recipients []string, hosts []string, addrs map[string]string) *SMTPSender {
	t.Helper()

	return NewSMTP(SMTPOptions{
		From:       "watchdog@mail.example.org",
		HELO:       "mail.example.org",
		Recipients: recipients,
		LookupMX: func(context.Context, string) ([]string, error) {
			return hosts, nil
		},
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			// The MX name is resolved through the test's table rather than DNS.
			host, _, _ := net.SplitHostPort(addr)
			real, ok := addrs[host]
			if !ok {
				return nil, errors.New("no such host: " + host)
			}
			d := &net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "tcp4", real)
		},
		Now: func() time.Time { return testClock },
	}, nil)
}

func TestSMTPDeliversToTheMX(t *testing.T) {
	mx := startFakeMX(t, "")
	sender := senderTo(t, []string{"admin@example.org"},
		[]string{"mx.example.org"},
		map[string]string{"mx.example.org": mx.addr})

	err := sender.Send(context.Background(), Message{
		Service: "nginx-mailcow",
		Subject: "Watchdog ALERT: nginx-mailcow",
		Body:    "HTTP CRITICAL: connection refused",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	got := mx.snapshot()
	if got.From != "watchdog@mail.example.org" {
		t.Errorf("MAIL FROM = %q", got.From)
	}
	if len(got.To) != 1 || got.To[0] != "admin@example.org" {
		t.Errorf("RCPT TO = %v", got.To)
	}
	// smtp-cli announced MAILCOW_HOSTNAME so the greeting matches the sender.
	if got.HELO != "mail.example.org" {
		t.Errorf("EHLO = %q, want the mailcow hostname", got.HELO)
	}

	for _, want := range []string{
		"Subject: Watchdog ALERT: nginx-mailcow",
		"From: watchdog@mail.example.org",
		"To: admin@example.org",
		"X-Priority: 1",
		"Content-Type: text/plain; charset=UTF-8",
		"HTTP CRITICAL: connection refused",
	} {
		if !strings.Contains(got.Data, want) {
			t.Errorf("message is missing %q:\n%s", want, got.Data)
		}
	}
}

// A domain with no MX cannot be delivered to; the shell skipped the whole
// notification in that case.
func TestSMTPWithoutAnMXIsAnError(t *testing.T) {
	sender := NewSMTP(SMTPOptions{
		From:       "watchdog@mail.example.org",
		HELO:       "mail.example.org",
		Recipients: []string{"admin@example.org"},
		LookupMX:   func(context.Context, string) ([]string, error) { return nil, nil },
		Now:        func() time.Time { return testClock },
	}, nil)

	err := sender.Send(context.Background(), Message{Subject: "x"})
	if err == nil || !strings.Contains(err.Error(), "no MX record") {
		t.Errorf("Send error = %v, want it to name the missing MX", err)
	}
}

// Exchangers are tried in preference order, like any MTA would.
func TestSMTPFallsBackToTheSecondaryMX(t *testing.T) {
	backup := startFakeMX(t, "")
	sender := senderTo(t, []string{"admin@example.org"},
		[]string{"primary.example.org", "backup.example.org"},
		map[string]string{"backup.example.org": backup.addr})

	if err := sender.Send(context.Background(), Message{Subject: "x", Body: "y"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := backup.snapshot(); got.From == "" {
		t.Error("the backup exchanger was never used")
	}
}

// One unreachable recipient domain must not stop the others.
func TestSMTPKeepsGoingAfterAFailingRecipient(t *testing.T) {
	mx := startFakeMX(t, "")
	sender := NewSMTP(SMTPOptions{
		From:       "watchdog@mail.example.org",
		HELO:       "mail.example.org",
		Recipients: []string{"broken@nowhere.invalid", "admin@example.org"},
		LookupMX: func(_ context.Context, domain string) ([]string, error) {
			if domain == "nowhere.invalid" {
				return nil, errors.New("NXDOMAIN")
			}
			return []string{"mx.example.org"}, nil
		},
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "tcp4", mx.addr)
		},
		Now: func() time.Time { return testClock },
	}, nil)

	err := sender.Send(context.Background(), Message{Subject: "x", Body: "y"})
	if err == nil {
		t.Error("Send should report the recipient it could not resolve")
	}
	if got := mx.snapshot(); len(got.To) != 1 || got.To[0] != "admin@example.org" {
		t.Errorf("the reachable recipient was not delivered to: %v", got.To)
	}
}

func TestSMTPRejectedRecipientIsReported(t *testing.T) {
	mx := startFakeMX(t, "RCPT")
	sender := senderTo(t, []string{"admin@example.org"},
		[]string{"mx.example.org"},
		map[string]string{"mx.example.org": mx.addr})

	if err := sender.Send(context.Background(), Message{Subject: "x", Body: "y"}); err == nil {
		t.Error("Send should report a rejected RCPT TO")
	}
}

func TestNewSMTPWithoutRecipients(t *testing.T) {
	if NewSMTP(SMTPOptions{From: "watchdog@mail.example.org"}, nil) != nil {
		t.Error("a sender without recipients should not be constructed")
	}
}

// A German umlaut in an alert must not arrive as mojibake.
func TestEncodeHeader(t *testing.T) {
	if got := encodeHeader("Watchdog ALERT: nginx"); got != "Watchdog ALERT: nginx" {
		t.Errorf("ASCII should be left alone, got %q", got)
	}
	got := encodeHeader("Zertifikat läuft ab")
	if !strings.HasPrefix(got, "=?UTF-8?") {
		t.Errorf("encodeHeader = %q, want RFC 2047 encoding", got)
	}
}

// The dot-writer returned by smtp.Client.Data does the escaping, so this must
// not do it a second time.
func TestNormaliseNewlines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare newlines become CRLF", "a\nb", "a\r\nb\r\n"},
		{"existing CRLF is preserved", "a\r\nb\r\n", "a\r\nb\r\n"},
		{"a trailing break is added", "a", "a\r\n"},
		{"leading dots are left to the dot-writer", ".hidden\n", ".hidden\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normaliseNewlines(tc.in); got != tc.want {
				t.Errorf("normaliseNewlines(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
