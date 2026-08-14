package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// noSleep removes the retry delay so the loop costs a test nothing.
func noSleep(context.Context, time.Duration) error { return nil }

// The reflector is only reachable over IPv6 in production; here the transport is
// replaced so the loop itself can be tested on any machine.
func linkTo(t *testing.T, sources []string) *IPv6Link {
	t.Helper()

	p := NewIPv6Link(IPv6Options{Sources: sources, Sleep: noSleep})
	p.client = &http.Client{Timeout: time.Second}
	return p
}

func TestIPv6LinkReturnsTheReflectedAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("2001:db8::1\n"))
	}))
	defer srv.Close()

	got := linkTo(t, []string{srv.URL}).Address(context.Background())
	if got != "2001:db8::1" {
		t.Errorf("Address() = %q, want 2001:db8::1", got)
	}
}

// A reflector that answers with an IPv4 address, an error page or nonsense must
// not be mistaken for a working v6 link.
func TestIPv6LinkRejectsNonIPv6Answers(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"an IPv4 address", "203.0.113.7"},
		{"an error page", "<html>502 Bad Gateway</html>"},
		{"nothing at all", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			if got := linkTo(t, []string{srv.URL}).Address(context.Background()); got != "" {
				t.Errorf("Address() = %q, want an empty result", got)
			}
		})
	}
}

// One broken reflector must not decide the outcome, which is why the shell
// picked a random source per attempt.
func TestIPv6LinkFallsBackToTheOtherSource(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer broken.Close()

	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("2001:db8::2"))
	}))
	defer working.Close()

	got := linkTo(t, []string{broken.URL, working.URL}).Address(context.Background())
	if got != "2001:db8::2" {
		t.Errorf("Address() = %q, want the working reflector's answer", got)
	}
}

func TestIPv6LinkGivesUpAfterTheRetryBudget(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if got := linkTo(t, []string{srv.URL}).Address(context.Background()); got != "" {
		t.Errorf("Address() = %q, want an empty result", got)
	}
	if got := hits.Load(); got != ipv6Attempts {
		t.Errorf("made %d attempts, want %d", got, ipv6Attempts)
	}
}

func TestIPv6LinkHonoursCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := NewIPv6Link(IPv6Options{Sources: []string{srv.URL}})
	if got := p.Address(ctx); got != "" {
		t.Errorf("Address() = %q on a cancelled context, want an empty result", got)
	}
}

// The link check only runs when the bridge actually carries an address in the
// configured network, so a stack without IPv6 stays quiet.
func TestIPv6Configured(t *testing.T) {
	tests := []struct {
		name    string
		network string
		addrs   []string
		want    bool
		wantErr bool
	}{
		{
			name:    "an address inside the network",
			network: "fd4d:6169:6c63:6f77::/64",
			addrs:   []string{"fd4d:6169:6c63:6f77::2/64", "172.22.1.5/24"},
			want:    true,
		},
		{
			name:    "only IPv4",
			network: "fd4d:6169:6c63:6f77::/64",
			addrs:   []string{"172.22.1.5/24", "127.0.0.1/8"},
			want:    false,
		},
		{
			// A substring match on the first three hextets, as the shell did,
			// would call this a hit.
			name:    "a different IPv6 network",
			network: "fd4d:6169:6c63:6f77::/64",
			addrs:   []string{"fd4d:6169:6c63:9999::2/64"},
			want:    false,
		},
		{
			name:    "no network configured",
			network: "",
			addrs:   []string{"fd4d:6169:6c63:6f77::2/64"},
			want:    false,
		},
		{
			name:    "a malformed network",
			network: "not-a-network",
			addrs:   nil,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addrs := func() ([]net.Addr, error) {
				var out []net.Addr
				for _, raw := range tc.addrs {
					ip, network, err := net.ParseCIDR(raw)
					if err != nil {
						t.Fatalf("parsing %q: %v", raw, err)
					}
					out = append(out, &net.IPNet{IP: ip, Mask: network.Mask})
				}
				return out, nil
			}

			got, err := IPv6Configured(tc.network, addrs)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("IPv6Configured: %v", err)
			}
			if got != tc.want {
				t.Errorf("IPv6Configured = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLocalAddrs(t *testing.T) {
	// Every machine has at least a loopback address.
	addrs, err := LocalAddrs()
	if err != nil {
		t.Fatalf("LocalAddrs: %v", err)
	}
	if len(addrs) == 0 {
		t.Error("LocalAddrs returned nothing")
	}
}
