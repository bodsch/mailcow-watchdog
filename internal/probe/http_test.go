package probe

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"bodsch.me/mailcow-watchdog/internal/health"
)

// splitHostPort turns an httptest server URL into the pieces the probes take.
func splitHostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()

	rawURL = strings.TrimPrefix(rawURL, "http://")
	host, portStr, err := net.SplitHostPort(rawURL)
	if err != nil {
		t.Fatalf("splitting %q: %v", rawURL, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parsing port %q: %v", portStr, err)
	}
	return host, port
}

// Nagios graded 2xx and 3xx as OK, 4xx as WARNING and 5xx as CRITICAL, which is
// what makes a 404 cost one error point and a 502 cost two.
func TestHTTPStatusGrading(t *testing.T) {
	tests := []struct {
		code   int
		want   health.Status
		points int
	}{
		{http.StatusOK, health.StatusOK, 0},
		{http.StatusFound, health.StatusOK, 0},
		{http.StatusNotFound, health.StatusWarning, 1},
		{http.StatusInternalServerError, health.StatusCritical, 2},
		{http.StatusBadGateway, health.StatusCritical, 2},
	}

	for _, tc := range tests {
		t.Run(http.StatusText(tc.code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()

			host, port := splitHostPort(t, srv.URL)
			res := runProbe(t, NewHTTP("nginx", Static(host), port, "/"))

			if res.Status != tc.want {
				t.Errorf("status = %v (%s), want %v", res.Status, res.Message, tc.want)
			}
			if res.Weight() != tc.points {
				t.Errorf("Weight() = %d, want %d", res.Weight(), tc.points)
			}
		})
	}
}

func TestHTTPRequestsTheConfiguredPath(t *testing.T) {
	// The handler runs on the server's goroutine, so the observation is passed
	// back through an atomic rather than a plain variable.
	var got atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.URL)
	// SOGo is probed on /SOGo.index/ rather than the document root.
	runProbe(t, NewHTTP("sogo", Static(host), port, "/SOGo.index/"))

	if got.Load() != "/SOGo.index/" {
		t.Errorf("requested path = %v, want /SOGo.index/", got.Load())
	}
}

// check_http reported a redirect rather than chasing it, so a 302 must not turn
// into whatever the target answers.
func TestHTTPDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/broken", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.URL)
	res := runProbe(t, NewHTTP("nginx", Static(host), port, "/"))

	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK for a 302", res.Status, res.Message)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server was hit %d times, want 1", got)
	}
}

func TestHTTPUnreachableIsCritical(t *testing.T) {
	host, port := closedPort(t)
	res := runProbe(t, NewHTTP("nginx", Static(host), port, "/"))

	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
}
