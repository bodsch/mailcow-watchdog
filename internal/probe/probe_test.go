package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"bodsch.me/mailcow-watchdog/internal/health"
)

// stubProbe returns a fixed result, for exercising the wrappers.
type stubProbe struct {
	name string
	res  Result
	fn   func() Result
}

func (p *stubProbe) Name() string { return p.name }

func (p *stubProbe) Run(context.Context) Result {
	if p.fn != nil {
		return p.fn()
	}
	return p.res
}

// Cost exists because watchdog.sh was not uniform: probes that shelled out to a
// Nagios plugin folded in its exit code, while the ones it implemented itself
// always added exactly one point.
func TestCostOverridesFailurePoints(t *testing.T) {
	tests := []struct {
		name   string
		inner  Result
		want   int
		status health.Status
	}{
		{"critical becomes one point", Critical("boom"), 1, health.StatusCritical},
		{"unknown becomes one point", Unknown("no idea"), 1, health.StatusUnknown},
		{"warning stays one point", Warning("meh"), 1, health.StatusWarning},
		{"success still costs nothing", OK("fine"), 0, health.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Cost(1, &stubProbe{name: "acme", res: tc.inner})
			res := runProbe(t, p)

			if res.Weight() != tc.want {
				t.Errorf("Weight() = %d, want %d", res.Weight(), tc.want)
			}
			// The severity is preserved for logs and metrics even when the cost
			// is flattened.
			if res.Status != tc.status {
				t.Errorf("Status = %v, want %v", res.Status, tc.status)
			}
			if res.Probe != "acme" {
				t.Errorf("Probe = %q, want the inner name to survive", res.Probe)
			}
		})
	}
}

// Without Cost, the error points are the Nagios exit code itself.
func TestDefaultPointsAreTheNagiosExitCode(t *testing.T) {
	tests := []struct {
		res  Result
		want int
	}{
		{OK("ok"), 0},
		{Warning("warn"), 1},
		{Critical("crit"), 2},
		{Unknown("unknown"), 3},
	}
	for _, tc := range tests {
		if got := tc.res.Weight(); got != tc.want {
			t.Errorf("%v: Weight() = %d, want %d", tc.res.Status, got, tc.want)
		}
	}
}

// A bug in one probe must not take down the whole watchdog.
func TestRunRecoversFromPanics(t *testing.T) {
	p := &stubProbe{name: "boom", fn: func() Result { panic("nil map") }}

	res := runProbe(t, p)
	if res.Status != health.StatusUnknown {
		t.Errorf("status = %v, want UNKNOWN", res.Status)
	}
	if !strings.Contains(res.Message, "panicked") {
		t.Errorf("message = %q, want it to report the panic", res.Message)
	}
	if res.Probe != "boom" {
		t.Errorf("Probe = %q, want the name to be stamped even after a panic", res.Probe)
	}
}

func TestStaticAddr(t *testing.T) {
	got, err := Static("172.22.1.5")(context.Background())
	if err != nil || got != "172.22.1.5" {
		t.Errorf("Static = (%q, %v), want the host back unchanged", got, err)
	}
}

func TestMailqCountsDeferredFiles(t *testing.T) {
	dir := t.TempDir()
	// Postfix spreads the queue across hashed subdirectories.
	for _, sub := range []string{"A", "B/C"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	for _, name := range []string{"A/msg1", "A/msg2", "B/C/msg3"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	if res := runProbe(t, NewMailq("mailq", dir, 30)); res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK for 3 of 30", res.Status, res.Message)
	}
	if !strings.Contains(runProbe(t, NewMailq("mailq", dir, 30)).Message, "contains 3 items") {
		t.Error("message should report the queue size")
	}

	// MAILQ_CRIT is inclusive: reaching it is already critical.
	if res := runProbe(t, NewMailq("mailq", dir, 3)); res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL at the limit", res.Status, res.Message)
	}
}

// Postfix creates the deferred directory lazily, so its absence means an empty
// queue rather than a broken mount.
func TestMailqMissingDirectoryIsEmpty(t *testing.T) {
	res := runProbe(t, NewMailq("mailq", filepath.Join(t.TempDir(), "nope"), 30))
	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "contains 0 items") {
		t.Errorf("message = %q, want a queue size of zero", res.Message)
	}
}

func TestExternalReportsOpenRelay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("guid") != "GUID-1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"response":"critical","out":"port 25 accepts relaying"}`))
	}))
	defer srv.Close()

	guid := func(context.Context) (string, error) { return "GUID-1", nil }
	p := NewExternal("external-ipv4", "tcp4", srv.URL, guid)

	res := runProbe(t, p)
	if res.Status != health.StatusCritical {
		t.Fatalf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
	// Each address family keeps its own transcript; the shell stored the IPv4
	// body even when it was the IPv6 test that failed.
	if got := p.Details(); got != "port 25 accepts relaying" {
		t.Errorf("Details() = %q, want the report body", got)
	}
}

func TestExternalHealthyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"response":"ok"}`))
	}))
	defer srv.Close()

	guid := func(context.Context) (string, error) { return "GUID-1", nil }
	res := runProbe(t, NewExternal("external-ipv4", "tcp4", srv.URL, guid))

	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
}

// The endpoint being down says nothing about this installation, so it must not
// count against the error budget.
func TestExternalUnreachableEndpointIsNotAFailure(t *testing.T) {
	host, port := closedPort(t)
	guid := func(context.Context) (string, error) { return "GUID-1", nil }

	url := "http://" + net.JoinHostPort(host, strconv.Itoa(port))
	res := runProbe(t, NewExternal("external-ipv4", "tcp4", url, guid))

	if res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
}

func TestExternalMissingGUIDIsUnknown(t *testing.T) {
	guid := func(context.Context) (string, error) { return "", errors.New("database is down") }

	res := runProbe(t, NewExternal("external-ipv4", "tcp4", "http://127.0.0.1:1", guid))
	if res.Status != health.StatusUnknown {
		t.Errorf("status = %v (%s), want UNKNOWN", res.Status, res.Message)
	}
}

func TestRspamdSettingsScore(t *testing.T) {
	tests := []struct {
		name string
		body string
		want health.Status
	}{
		{"settings applied", `{"default":{"required_score":9999.0}}`, health.StatusOK},
		{"decimals ignored", `{"default":{"required_score":9999.9}}`, health.StatusOK},
		{"settings missing", `{"default":{"required_score":15.0}}`, health.StatusCritical},
		{"unparsable", `not json`, health.StatusCritical},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			socket := socketPath(t)
			srv := unixServer(t, socket, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/scan" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = w.Write([]byte(tc.body))
			})
			defer srv.Close()

			res := runProbe(t, NewRspamd("rspamd", socket))
			if res.Status != tc.want {
				t.Errorf("status = %v (%s), want %v", res.Status, res.Message, tc.want)
			}
		})
	}
}

func TestRspamdUnreachableSocketIsCritical(t *testing.T) {
	res := runProbe(t, NewRspamd("rspamd", filepath.Join(t.TempDir(), "absent.sock")))
	if res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
}

// unixServer serves handler over a unix socket, the way rspamd's normal worker
// is reached from the watchdog container.
func unixServer(t *testing.T, socket string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen on %s: %v", socket, err)
	}
	srv := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: handler},
	}
	srv.Start()
	return srv
}

// socketPath returns a path short enough for a unix socket. t.TempDir() nests
// the test name into the path, which overruns the ~100 byte sun_path limit.
func socketPath(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "wd")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	return filepath.Join(dir, "rspamd.sock")
}
