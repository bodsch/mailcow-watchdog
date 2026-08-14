package probe

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"bodsch.me/mailcow-watchdog/internal/health"
	"github.com/miekg/dns"
)

// dnsServer starts a UDP resolver on an ephemeral loopback port and answers
// every query with handle.
func dnsServer(t *testing.T, handle dns.HandlerFunc) (string, int) {
	t.Helper()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &dns.Server{PacketConn: conn, Handler: handle}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }

	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })

	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP.String(), addr.Port
}

func TestDNSSuccess(t *testing.T) {
	host, port := dnsServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name: req.Question[0].Name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: 60,
			},
			A: net.ParseIP("203.0.113.10"),
		})
		_ = w.WriteMsg(m)
	})

	res := runProbe(t, NewDNS("unbound", Static(host), port, "stackoverflow.com"))
	if res.Status != health.StatusOK {
		t.Fatalf("status = %v (%s), want OK", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "203.0.113.10") {
		t.Errorf("message = %q, want it to list the answer", res.Message)
	}
	if !strings.Contains(res.Message, "seconds response time") {
		t.Errorf("message = %q, want it to report the response time", res.Message)
	}
}

func TestDNSServfailIsCritical(t *testing.T) {
	host, port := dnsServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})

	res := runProbe(t, NewDNS("unbound", Static(host), port, "stackoverflow.com"))
	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
}

// check_dns.sh treated an empty answer as "domain was not found", even though
// dig exits zero for a NOERROR with no records.
func TestDNSEmptyAnswerIsCritical(t *testing.T) {
	host, port := dnsServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		_ = w.WriteMsg(m)
	})

	res := runProbe(t, NewDNS("unbound", Static(host), port, "stackoverflow.com"))
	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "no address") {
		t.Errorf("message = %q, want it to say no address was returned", res.Message)
	}
}

// DNSSEC validation is proved by the authenticated-data flag, which a resolver
// only sets when it verified the signatures itself.
func TestDNSSECAuthenticatedData(t *testing.T) {
	tests := []struct {
		name string
		ad   bool
		want health.Status
	}{
		{"validated", true, health.StatusOK},
		{"not validated", false, health.StatusCritical},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port := dnsServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
				m := new(dns.Msg)
				m.SetReply(req)
				m.AuthenticatedData = tc.ad
				_ = w.WriteMsg(m)
			})

			res := runProbe(t, NewDNSSEC("unbound-dnssec", Static(host), port, "com"))
			if res.Status != tc.want {
				t.Errorf("status = %v (%s), want %v", res.Status, res.Message, tc.want)
			}
		})
	}
}

// The DO bit is what makes a resolver validate at all; without it the AD flag
// would never be set and the check would fail for the wrong reason.
func TestDNSSECSetsTheDOBit(t *testing.T) {
	// The flag is written on the resolver's goroutine and read on the test's.
	var sawDO atomic.Bool

	host, port := dnsServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			sawDO.Store(true)
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.AuthenticatedData = true
		_ = w.WriteMsg(m)
	})

	runProbe(t, NewDNSSEC("unbound-dnssec", Static(host), port, "com"))
	if !sawDO.Load() {
		t.Error("the DNSSEC probe must set the DO bit, or the resolver has no reason to validate")
	}
}

func TestDNSUnreachableResolverIsCritical(t *testing.T) {
	// Port 1 on loopback has nothing listening, and UDP gives an ICMP refusal.
	res := runProbe(t, NewDNS("unbound", Static("127.0.0.1"), 1, "stackoverflow.com"))
	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
}
