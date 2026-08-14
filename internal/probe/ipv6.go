package probe

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"
)

// IPv6Sources are the reflectors that report back the address they saw. Two of
// them, so one being down is not mistaken for a broken link.
var IPv6Sources = []string{
	"https://ip6.mailcow.email",
	"https://ip6.nevondo.com",
}

// ipv6Attempts and ipv6ConnectTimeout mirror the shell's retry loop:
// `curl --connect-timeout 3 -m 10 -L6s`, up to ten times, one second apart.
const (
	ipv6Attempts       = 10
	ipv6ConnectTimeout = 3 * time.Second
	ipv6RequestTimeout = 10 * time.Second
	ipv6RetryDelay     = time.Second
)

// IPv6Link determines the installation's public IPv6 address.
//
// This is watchdog.sh's get_ipv6, and it runs once at startup rather than on a
// loop. mailcow's docker-compose can enable IPv6 on the bridge; when it does but
// the host has no working IPv6 route, outbound mail to v6-only exchangers fails
// in a way that is very hard to attribute later. Detecting it once, loudly, at
// startup is worth more than a recurring check.
type IPv6Link struct {
	sources []string
	client  *http.Client
	sleep   func(context.Context, time.Duration) error
}

// IPv6Options configures the lookup.
type IPv6Options struct {
	// Sources defaults to IPv6Sources.
	Sources []string
	// Sleep defaults to a context-aware time.Sleep and is replaced in tests so
	// the retry loop costs nothing.
	Sleep func(context.Context, time.Duration) error
}

// NewIPv6Link returns an IPv6 reachability check.
func NewIPv6Link(opts IPv6Options) *IPv6Link {
	if len(opts.Sources) == 0 {
		opts.Sources = IPv6Sources
	}
	if opts.Sleep == nil {
		opts.Sleep = func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-timer.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return &IPv6Link{
		sources: opts.Sources,
		sleep:   opts.Sleep,
		client: &http.Client{
			Timeout: ipv6RequestTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
					// Forcing tcp6 is the whole point: a reflector reachable
					// over IPv4 would say nothing about the v6 link.
					d := &net.Dialer{Timeout: ipv6ConnectTimeout}
					return d.DialContext(ctx, "tcp6", addr)
				},
				DisableKeepAlives: true,
			},
		},
	}
}

// Address returns the public IPv6 address, or an empty string when no source
// answered within the retry budget.
func (p *IPv6Link) Address(ctx context.Context) string {
	for attempt := 0; attempt < ipv6Attempts; attempt++ {
		if attempt > 0 {
			if err := p.sleep(ctx, ipv6RetryDelay); err != nil {
				return ""
			}
		}
		// A random source per attempt, so a single broken reflector cannot
		// dominate the result.
		source := p.sources[rand.N(len(p.sources))] //nolint:gosec // G404: load spreading, not security

		if addr := p.ask(ctx, source); addr != "" {
			return addr
		}
	}
	return ""
}

func (p *IPv6Link) ask(ctx context.Context, source string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return ""
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if err != nil {
		return ""
	}

	candidate := strings.TrimSpace(string(body))
	if ip := net.ParseIP(candidate); ip != nil && ip.To4() == nil {
		return candidate
	}
	return ""
}

// IPv6Configured reports whether any local interface carries an address inside
// network.
//
// The shell did this by grepping the first three hextets of IPV6_NETWORK out of
// `ip a s`. Parsing the prefix properly and testing containment is the same test
// without the false positives a substring match invites.
func IPv6Configured(network string, addrs func() ([]net.Addr, error)) (bool, error) {
	if strings.TrimSpace(network) == "" {
		return false, nil
	}

	_, prefix, err := net.ParseCIDR(strings.TrimSpace(network))
	if err != nil {
		return false, fmt.Errorf("IPV6_NETWORK %q is not a network in CIDR form: %w", network, err)
	}

	local, err := addrs()
	if err != nil {
		return false, fmt.Errorf("reading the local interface addresses: %w", err)
	}

	for _, addr := range local {
		ip := addrIP(addr)
		if ip == nil || ip.To4() != nil {
			continue
		}
		if prefix.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// LocalAddrs is the production source of interface addresses.
func LocalAddrs() ([]net.Addr, error) { return net.InterfaceAddrs() }

func addrIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}
