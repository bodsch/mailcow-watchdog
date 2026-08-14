package probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// dnsQueryTimeout matches `dig +timeout=2 +tries=1` from check_dns.sh: one
// attempt, two seconds. A resolver that needs longer is already unhealthy.
const dnsQueryTimeout = 2 * time.Second

// DNSPort is where unbound-mailcow listens. It is a constructor argument rather
// than a constant inside the probe so that the probes can be tested against a
// resolver on an ephemeral port.
const DNSPort = 53

// DNS replaces check_dns.sh: it asks a specific resolver for a name and reports
// how long the answer took.
type DNS struct {
	name     string
	resolver Addr
	port     int
	query    string
}

// NewDNS returns a lookup probe. The original queried stackoverflow.com through
// unbound-mailcow, i.e. it deliberately tested full recursion rather than a
// cached local zone.
func NewDNS(name string, resolver Addr, port int, query string) *DNS {
	return &DNS{name: name, resolver: resolver, port: port, query: dns.Fqdn(query)}
}

// Name implements Probe.
func (p *DNS) Name() string { return p.name }

// Run implements Probe.
func (p *DNS) Run(ctx context.Context) Result {
	server, bad := resolve(ctx, p.resolver, p.name)
	if bad != nil {
		return *bad
	}

	msg := new(dns.Msg)
	msg.SetQuestion(p.query, dns.TypeA)
	msg.RecursionDesired = true

	start := time.Now()
	reply, err := exchange(ctx, msg, server, p.port)
	elapsed := time.Since(start)

	if err != nil {
		return Critical("%s: %s was not answered by %s: %v", p.name, p.query, server, err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		return Critical("%s: %s was answered by %s with %s",
			p.name, p.query, server, dns.RcodeToString[reply.Rcode])
	}

	var addrs []string
	for _, rr := range reply.Answer {
		if a, ok := rr.(*dns.A); ok {
			addrs = append(addrs, a.A.String())
		}
	}
	if len(addrs) == 0 {
		// An empty but successful answer is the "domain was not found" case the
		// shell version caught by testing dig's output for emptiness.
		return Critical("%s: %s returned no address from %s", p.name, p.query, server)
	}

	return OK("%s: %.3f seconds response time, %s returns %s",
		p.name, elapsed.Seconds(), p.query, strings.Join(addrs, ","))
}

// DNSSEC verifies that the resolver validates signatures, by requiring the
// authenticated-data flag on a signed zone.
//
// watchdog.sh ran `dig com +dnssec | egrep 'flags:.+ad'` against the container's
// default resolver. This queries the unbound container directly instead, so the
// probe still tests unbound when a deployment's resolv.conf points elsewhere.
type DNSSEC struct {
	name     string
	resolver Addr
	port     int
	zone     string
}

// NewDNSSEC returns a DNSSEC validation probe.
func NewDNSSEC(name string, resolver Addr, port int, zone string) *DNSSEC {
	return &DNSSEC{name: name, resolver: resolver, port: port, zone: dns.Fqdn(zone)}
}

// Name implements Probe.
func (p *DNSSEC) Name() string { return p.name }

// Run implements Probe.
func (p *DNSSEC) Run(ctx context.Context) Result {
	server, bad := resolve(ctx, p.resolver, p.name)
	if bad != nil {
		return *bad
	}

	msg := new(dns.Msg)
	msg.SetQuestion(p.zone, dns.TypeSOA)
	msg.RecursionDesired = true
	// SetEdns0 with the DO bit is what `dig +dnssec` sends; without it the
	// resolver has no reason to validate or to set AD.
	msg.SetEdns0(4096, true)

	reply, err := exchange(ctx, msg, server, p.port)
	if err != nil {
		return Critical("%s: DNSSEC query for %s failed: %v", p.name, p.zone, err)
	}
	if !reply.AuthenticatedData {
		return Critical("%s: %s answered %s without the authenticated-data flag",
			p.name, server, p.zone)
	}
	return OK("%s: %s validated %s", p.name, server, p.zone)
}

// exchange sends a query over UDP, retrying over TCP when the answer is
// truncated. The context deadline still applies, but the per-query timeout is
// the tighter of the two.
func exchange(ctx context.Context, msg *dns.Msg, server string, port int) (*dns.Msg, error) {
	addr := net.JoinHostPort(server, strconv.Itoa(port))

	queryCtx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
	defer cancel()

	udp := &dns.Client{Net: "udp", Timeout: dnsQueryTimeout}
	reply, _, err := udp.ExchangeContext(queryCtx, msg, addr)
	if err != nil {
		return nil, err
	}
	if !reply.Truncated {
		return reply, nil
	}

	tcpCtx, cancelTCP := context.WithTimeout(ctx, dnsQueryTimeout)
	defer cancelTCP()

	tcp := &dns.Client{Net: "tcp", Timeout: dnsQueryTimeout}
	reply, _, err = tcp.ExchangeContext(tcpCtx, msg, addr)
	if err != nil {
		return nil, fmt.Errorf("retrying truncated answer over TCP: %w", err)
	}
	return reply, nil
}
