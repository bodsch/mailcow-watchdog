package whois

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

// whoisServer answers one query per connection with a canned record and records
// what it was asked.
func whoisServer(t *testing.T, record string) (addr string, queries func() []string) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var (
		mu   sync.Mutex
		seen []string
	)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return
				}
				mu.Lock()
				seen = append(seen, strings.TrimSpace(line))
				mu.Unlock()
				_, _ = conn.Write([]byte(record))
			}()
		}
	}()

	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// clientFor builds a client whose lookups are routed to the test servers by
// name rather than through DNS.
func clientFor(t *testing.T, root string, servers map[string]string) *Client {
	t.Helper()

	return New(Options{
		Root:    root,
		Timeout: 2 * time.Second,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			real, ok := servers[host]
			if !ok {
				return nil, errors.New("no such whois server: " + host)
			}
			d := &net.Dialer{}
			return d.DialContext(ctx, "tcp4", real)
		},
	})
}

// IANA answers for every address but only with a pointer to the responsible
// regional registry, so the referral has to be followed to get anything useful.
func TestLookupFollowsTheReferral(t *testing.T) {
	ripeAddr, ripeQueries := whoisServer(t, "netname: EXAMPLE-NET\ncountry: DE\n")
	ianaAddr, ianaQueries := whoisServer(t, "refer: whois.ripe.net\n\ninetnum: 198.51.100.0 - 198.51.100.255\n")

	client := clientFor(t, "whois.iana.org", map[string]string{
		"whois.iana.org": ianaAddr,
		"whois.ripe.net": ripeAddr,
	})

	got, err := client.Lookup(context.Background(), "198.51.100.7")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !strings.Contains(got, "netname: EXAMPLE-NET") {
		t.Errorf("Lookup = %q, want the regional registry's record", got)
	}

	if q := ianaQueries(); len(q) != 1 || q[0] != "198.51.100.7" {
		t.Errorf("IANA was asked %v, want the address", q)
	}
	if q := ripeQueries(); len(q) != 1 || q[0] != "198.51.100.7" {
		t.Errorf("RIPE was asked %v, want the address", q)
	}
}

// A partial record beats none: if the referral cannot be reached, the root
// answer still names the registry.
func TestLookupFallsBackToTheRootAnswer(t *testing.T) {
	ianaAddr, _ := whoisServer(t, "refer: whois.unreachable.invalid\n\ninetnum: 198.51.100.0\n")

	client := clientFor(t, "whois.iana.org", map[string]string{"whois.iana.org": ianaAddr})

	got, err := client.Lookup(context.Background(), "198.51.100.7")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !strings.Contains(got, "inetnum: 198.51.100.0") {
		t.Errorf("Lookup = %q, want the root answer", got)
	}
}

func TestLookupWithoutAReferral(t *testing.T) {
	ianaAddr, _ := whoisServer(t, "inetnum: 198.51.100.0 - 198.51.100.255\n")

	client := clientFor(t, "whois.iana.org", map[string]string{"whois.iana.org": ianaAddr})

	got, err := client.Lookup(context.Background(), "198.51.100.7")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !strings.Contains(got, "inetnum") {
		t.Errorf("Lookup = %q", got)
	}
}

func TestLookupUnreachableRootIsAnError(t *testing.T) {
	client := clientFor(t, "whois.iana.org", nil)

	if _, err := client.Lookup(context.Background(), "198.51.100.7"); err == nil {
		t.Error("Lookup should fail when the root server cannot be reached")
	}
}

func TestReferral(t *testing.T) {
	tests := []struct {
		name   string
		answer string
		want   string
	}{
		{"present", "inetnum: x\nrefer: whois.ripe.net\n", "whois.ripe.net"},
		{"case insensitive", "Refer: whois.arin.net\n", "whois.arin.net"},
		{"indented", "   refer:   whois.apnic.net  \n", "whois.apnic.net"},
		{"absent", "inetnum: x\n", ""},
		{"empty value", "refer:\n", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := referral(tc.answer); got != tc.want {
				t.Errorf("referral = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	c := New(Options{})
	if c.root != RootServer {
		t.Errorf("root = %q, want %q", c.root, RootServer)
	}
	if c.timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", c.timeout, DefaultTimeout)
	}
	if c.dial == nil {
		t.Error("New should install a default dialer")
	}
}
