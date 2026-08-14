package probe

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"bodsch.me/mailcow-watchdog/internal/health"
)

func TestTCPConnectOnly(t *testing.T) {
	// postfix-tlspol and php-fpm are probed with a bare connect.
	host, port := bannerServer(t, "")
	res := runProbe(t, NewTCP("tlspol", Static(host), port, TCPOptions{}))

	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
	if res.Probe != "tlspol" {
		t.Errorf("Probe = %q, want the probe name to be stamped", res.Probe)
	}
	if res.Duration <= 0 {
		t.Error("Duration should be measured")
	}
}

func TestTCPRefusedConnectionIsCritical(t *testing.T) {
	host, port := closedPort(t)
	res := runProbe(t, NewTCP("tlspol", Static(host), port, TCPOptions{}))

	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
	if res.Weight() != 2 {
		t.Errorf("Weight() = %d, want 2 error points for a CRITICAL", res.Weight())
	}
}

// Dovecot's ManageSieve and replication ports are graded on their banner.
func TestTCPExpect(t *testing.T) {
	tests := []struct {
		name   string
		banner string
		expect string
		want   health.Status
	}{
		{"managesieve", `"IMPLEMENTATION" "Dovecot ready."` + "\r\n", "Dovecot ready", health.StatusOK},
		{"replication", "VERSION\tdsync\t3\t0\n", "VERSION", health.StatusOK},
		{"wrong banner", "550 go away\r\n", "VERSION", health.StatusCritical},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port := bannerServer(t, tc.banner)
			res := runProbe(t, NewTCP("dovecot", Static(host), port, TCPOptions{Expect: tc.expect}))
			if res.Status != tc.want {
				t.Errorf("status = %v (%s), want %v", res.Status, res.Message, tc.want)
			}
		})
	}
}

// A banner that arrives in several writes must still satisfy the expectation.
func TestTCPExpectAcrossReads(t *testing.T) {
	host, port := listenLocal(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("* PREAMBLE\r\n"))
		time.Sleep(20 * time.Millisecond)
		_, _ = conn.Write([]byte("Dovecot ready.\r\n"))
	})

	res := runProbe(t, NewTCP("sieve", Static(host), port, TCPOptions{Expect: "Dovecot ready"}))
	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
}

func TestClamdPingPong(t *testing.T) {
	host, port := scriptedServer(t, "", []step{{Expect: "PING", Reply: "PONG\n"}})

	// NewClamd hard-codes clamd's port, so the conversation is exercised through
	// a plain TCP probe with the same options.
	res := runProbe(t, NewTCP("clamd", Static(host), port,
		TCPOptions{Send: "PING\n", Expect: "PONG"}))
	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}

	if got := NewClamd("clamd", Static("x")).port; got != 3310 {
		t.Errorf("NewClamd port = %d, want 3310", got)
	}
}

func TestTCPUnresolvableTargetIsUnknown(t *testing.T) {
	failing := func(context.Context) (string, error) { return "", errors.New("no such container") }
	res := runProbe(t, NewTCP("nginx", failing, 8081, TCPOptions{}))

	if res.Status != health.StatusUnknown {
		t.Errorf("status = %v (%s), want UNKNOWN", res.Status, res.Message)
	}
	if res.Weight() != 3 {
		t.Errorf("Weight() = %d, want 3 error points for an UNKNOWN", res.Weight())
	}
}

// The milter probe exists because rspamd's proxy worker has no ping: a wedged
// worker accepts the connection and then says nothing.
func TestMilterWedgedWorkerIsCritical(t *testing.T) {
	host, port := deadServer(t)
	res := runProbe(t, NewMilter("rspamd-milter", Static(host), port, 100*time.Millisecond))

	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "did not answer") {
		t.Errorf("message = %q, want it to name the timeout", res.Message)
	}
}

func TestMilterLiveWorkerIsOK(t *testing.T) {
	// A live worker hangs up on the bogus HTTP request rather than stalling.
	host, port := bannerServer(t, "")
	res := runProbe(t, NewMilter("rspamd-milter", Static(host), port, 2*time.Second))

	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
}

func TestMilterRefusedConnectionIsCritical(t *testing.T) {
	host, port := closedPort(t)
	res := runProbe(t, NewMilter("rspamd-milter", Static(host), port, time.Second))

	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
}

func TestTrimShortensAndFlattens(t *testing.T) {
	if got := trim("  550 no\r\n"); got != "550 no" {
		t.Errorf("trim = %q, want %q", got, "550 no")
	}
	long := strings.Repeat("x", 300)
	if got := trim(long); len(got) > 130 {
		t.Errorf("trim did not shorten a long banner: %d chars", len(got))
	}
}
