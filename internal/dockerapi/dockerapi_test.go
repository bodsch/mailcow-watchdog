package dockerapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// inspectJSON is one record as the mailcow dockerapi returns it, both in its
// container list and from its inspect endpoint: full inspect data with the
// compose labels under Config.
func inspectJSON(id, service, project string, networks map[string]string, startedAt string) map[string]any {
	return map[string]any{
		"Id": id,
		"Config": map[string]any{
			"Labels": map[string]string{
				composeServiceLabel: service,
				composeProjectLabel: project,
			},
		},
		"NetworkSettings": map[string]any{"Networks": networkJSON(networks)},
		"State":           map[string]any{"StartedAt": startedAt},
	}
}

// summaryJSON is one entry of the Docker daemon's container list: labels at the
// top level and State as a word rather than an object.
func summaryJSON(id, service, project string, networks map[string]string) map[string]any {
	return map[string]any{
		"Id": id,
		"Labels": map[string]string{
			composeServiceLabel: service,
			composeProjectLabel: project,
		},
		"State":           "running",
		"Status":          "Up 2 hours",
		"NetworkSettings": map[string]any{"Networks": networkJSON(networks)},
	}
}

func networkJSON(networks map[string]string) map[string]any {
	out := map[string]any{}
	for name, ip := range networks {
		out[name] = map[string]any{"IPAddress": ip}
	}
	return out
}

// httpsClient starts a fake mailcow dockerapi and returns a client for it.
func httpsClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client, err := New(Options{
		BaseURL:     srv.URL,
		Project:     "mailcowdockerized",
		IPv4Network: "172.22.1",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

// socketClient starts a fake Docker daemon on a unix socket and returns a client
// for it.
func socketClient(t *testing.T, handler http.HandlerFunc) (*Client, string) {
	t.Helper()

	// t.TempDir() nests the test name into the path, which overruns the ~100
	// byte sun_path limit.
	dir, err := os.MkdirTemp("/tmp", "wd")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socket := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen on %s: %v", socket, err)
	}

	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)

	client, err := New(Options{
		BaseURL:     "unix://" + socket,
		Project:     "mailcowdockerized",
		IPv4Network: "172.22.1",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, socket
}

func jsonHandler(t *testing.T, routes map[string]any) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("encoding the response: %v", err)
		}
	}
}

// The URL scheme picks the dialect unless it is set explicitly.
func TestDialectFollowsTheScheme(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		override Dialect
		want     Dialect
	}{
		{"https means the mailcow service", "https://dockerapi.x_mailcow-network", DialectAuto, DialectMailcow},
		{"http means the mailcow service", "http://dockerapi:8080", DialectAuto, DialectMailcow},
		{"a socket means the daemon", "unix:///var/run/docker.sock", DialectAuto, DialectEngine},
		{"an override wins", "unix:///var/run/dockerapi.sock", DialectMailcow, DialectMailcow},
		{"an override wins the other way", "https://dockerapi.x", DialectEngine, DialectEngine},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, err := New(Options{BaseURL: tc.url, Dialect: tc.override})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := client.Dialect(); got != tc.want {
				t.Errorf("Dialect() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNewRejectsUnusableURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"no scheme", "dockerapi.example", "no scheme"},
		{"unsupported scheme", "tcp://dockerapi:2375", "unsupported docker API scheme"},
		{"https without a host", "https://", "no host"},
		{"unix without a path", "unix://", "no socket path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Options{BaseURL: tc.url})
			if err == nil {
				t.Fatalf("New(%q) should fail", tc.url)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestParseDialect(t *testing.T) {
	tests := map[string]Dialect{
		"":        DialectAuto,
		"auto":    DialectAuto,
		"mailcow": DialectMailcow,
		"engine":  DialectEngine,
		"docker":  DialectEngine,
		"ENGINE":  DialectEngine,
		"  auto ": DialectAuto,
	}
	for input, want := range tests {
		got, err := ParseDialect(input)
		if err != nil {
			t.Errorf("ParseDialect(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("ParseDialect(%q) = %v, want %v", input, got, want)
		}
	}
	if _, err := ParseDialect("kubernetes"); err == nil {
		t.Error("ParseDialect should reject an unknown dialect")
	}
}

// Both dialects have to produce the same normalised container, or the supervisor
// would behave differently depending on how it was wired up.
func TestBothDialectsNormaliseTheSameWay(t *testing.T) {
	const started = "2026-08-14T06:30:00Z"

	mailcow := httpsClient(t, jsonHandler(t, map[string]any{
		"GET /containers/json": []map[string]any{
			inspectJSON("aaa", "nginx-mailcow", "mailcowdockerized",
				map[string]string{"mailcow-network": "172.22.1.5"}, started),
		},
	}))

	engine, _ := socketClient(t, jsonHandler(t, map[string]any{
		"GET /containers/json": []map[string]any{
			summaryJSON("aaa", "nginx-mailcow", "mailcowdockerized",
				map[string]string{"mailcow-network": "172.22.1.5"}),
		},
		"GET /containers/aaa/json": inspectJSON("aaa", "nginx-mailcow", "mailcowdockerized",
			map[string]string{"mailcow-network": "172.22.1.5"}, started),
	}))

	for name, client := range map[string]*Client{"mailcow": mailcow, "engine": engine} {
		t.Run(name, func(t *testing.T) {
			found, err := client.Find(context.Background(), "nginx-mailcow")
			if err != nil {
				t.Fatalf("Find: %v", err)
			}
			if len(found) != 1 {
				t.Fatalf("Find returned %d containers, want 1", len(found))
			}

			got := found[0]
			if got.ID != "aaa" || got.Service != "nginx-mailcow" || got.Project != "mailcowdockerized" {
				t.Errorf("normalised container = %+v", got)
			}
			if got.Networks["mailcow-network"] != "172.22.1.5" {
				t.Errorf("addresses = %v", got.Networks)
			}

			// The daemon's list carries no start time, so Find has to inspect.
			at, err := got.Started()
			if err != nil {
				t.Fatalf("Started: %v", err)
			}
			if want := time.Date(2026, 8, 14, 6, 30, 0, 0, time.UTC); !at.Equal(want) {
				t.Errorf("Started() = %v, want %v", at, want)
			}
		})
	}
}

// IP runs on every round of every check, so it must not pay for the extra
// inspection that Find needs.
func TestIPDoesNotInspect(t *testing.T) {
	var inspections int
	var mu sync.Mutex

	client, _ := socketClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				summaryJSON("aaa", "dovecot-mailcow", "mailcowdockerized",
					map[string]string{"mailcow-network": "172.22.1.250"}),
			})
		default:
			mu.Lock()
			inspections++
			mu.Unlock()
			w.WriteHeader(http.StatusNotFound)
		}
	})

	got, err := client.IP(context.Background(), "dovecot-mailcow")
	if err != nil {
		t.Fatalf("IP: %v", err)
	}
	if got != "172.22.1.250" {
		t.Errorf("IP = %q", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if inspections != 0 {
		t.Errorf("IP performed %d inspections, want none", inspections)
	}
}

// Several mailcow stacks can share a daemon, so the project label is what stops
// the watchdog from restarting a neighbouring stack's containers.
func TestListFiltersByProject(t *testing.T) {
	client := httpsClient(t, jsonHandler(t, map[string]any{
		"GET /containers/json": []map[string]any{
			inspectJSON("aaa", "nginx-mailcow", "mailcowdockerized",
				map[string]string{"mailcow-network": "172.22.1.5"}, ""),
			inspectJSON("bbb", "nginx-mailcow", "otherstack",
				map[string]string{"mailcow-network": "172.23.1.5"}, ""),
		},
	}))

	got, err := client.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].ID != "aaa" {
		t.Errorf("List returned %v, want only our own project's container", got)
	}
}

// Docker Compose lowercases project names, so the label may not match the
// configured value byte for byte.
func TestListMatchesProjectCaseInsensitively(t *testing.T) {
	client := httpsClient(t, jsonHandler(t, map[string]any{
		"GET /containers/json": []map[string]any{
			inspectJSON("aaa", "nginx-mailcow", "MailcowDockerized",
				map[string]string{"mailcow-network": "172.22.1.5"}, ""),
		},
	}))

	got, err := client.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("List returned %d containers, want 1", len(got))
	}
}

// A container attached to several networks also answers on addresses this host
// cannot reach; only the one on the mailcow bridge is usable.
func TestIPPicksTheMailcowNetwork(t *testing.T) {
	client := httpsClient(t, jsonHandler(t, map[string]any{
		"GET /containers/json": []map[string]any{
			inspectJSON("aaa", "dovecot-mailcow", "mailcowdockerized", map[string]string{
				"bridge":          "10.5.0.2",
				"mailcow-network": "172.22.1.250",
			}, ""),
		},
	}))

	got, err := client.IP(context.Background(), "dovecot-mailcow")
	if err != nil {
		t.Fatalf("IP: %v", err)
	}
	if got != "172.22.1.250" {
		t.Errorf("IP = %q, want the address on the mailcow bridge", got)
	}
}

// The service match is exact. watchdog.sh compared exactly here but used a
// substring match when restarting, and asking for "postfix" instead of
// "postfix-mailcow" is why its certificate check resolved nothing.
func TestFindMatchesTheServiceNameExactly(t *testing.T) {
	client := httpsClient(t, jsonHandler(t, map[string]any{
		"GET /containers/json": []map[string]any{
			inspectJSON("aaa", "postfix-mailcow", "mailcowdockerized",
				map[string]string{"mailcow-network": "172.22.1.253"}, ""),
			inspectJSON("bbb", "postfix-tlspol-mailcow", "mailcowdockerized",
				map[string]string{"mailcow-network": "172.22.1.252"}, ""),
		},
	}))

	matched, err := client.Find(context.Background(), "postfix-mailcow")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(matched) != 1 || matched[0].ID != "aaa" {
		t.Errorf("Find returned %v, want only the postfix-mailcow container", matched)
	}

	// The name the shell's certificate check used matches nothing.
	if matched, err := client.Find(context.Background(), "postfix"); err != nil {
		t.Fatalf("Find: %v", err)
	} else if len(matched) != 0 {
		t.Errorf("Find(%q) matched %d containers, want none", "postfix", len(matched))
	}
}

func TestIPUnknownServiceIsAnError(t *testing.T) {
	client := httpsClient(t, jsonHandler(t, map[string]any{
		"GET /containers/json": []map[string]any{},
	}))

	if _, err := client.IP(context.Background(), "nginx-mailcow"); err == nil {
		t.Error("IP should fail when no container runs the service")
	} else if !strings.Contains(err.Error(), "nginx-mailcow") {
		t.Errorf("error = %q, want it to name the service", err)
	}
}

func TestIPWithoutAnAddressOnOurNetwork(t *testing.T) {
	client := httpsClient(t, jsonHandler(t, map[string]any{
		"GET /containers/json": []map[string]any{
			inspectJSON("aaa", "nginx-mailcow", "mailcowdockerized",
				map[string]string{"bridge": "10.5.0.2"}, ""),
		},
	}))

	if _, err := client.IP(context.Background(), "nginx-mailcow"); err == nil {
		t.Error("IP should fail when the container has no address on the mailcow network")
	}
}

// A scaled service has several containers, and probes should spread across them.
func TestIPSpreadsAcrossScaledReplicas(t *testing.T) {
	client := httpsClient(t, jsonHandler(t, map[string]any{
		"GET /containers/json": []map[string]any{
			inspectJSON("aaa", "sogo-mailcow", "mailcowdockerized",
				map[string]string{"mailcow-network": "172.22.1.10"}, ""),
			inspectJSON("bbb", "sogo-mailcow", "mailcowdockerized",
				map[string]string{"mailcow-network": "172.22.1.11"}, ""),
		},
	}))

	seen := map[string]bool{}
	for i := 0; i < 60; i++ {
		ip, err := client.IP(context.Background(), "sogo-mailcow")
		if err != nil {
			t.Fatalf("IP: %v", err)
		}
		seen[ip] = true
	}
	if len(seen) != 2 {
		t.Errorf("saw addresses %v, want both replicas to be used", seen)
	}
}

func TestContainerStarted(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
		zero    bool
	}{
		{name: "normal", raw: "2026-08-14T06:30:00.123456789Z"},
		{name: "never started", raw: "0001-01-01T00:00:00Z", zero: true},
		{name: "absent", raw: "", zero: true},
		{name: "malformed", raw: "yesterday", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Container{StartedAt: tc.raw}.Started()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Started: %v", err)
			}
			if got.IsZero() != tc.zero {
				t.Errorf("Started() = %v, want zero == %v", got, tc.zero)
			}
		})
	}
}

func TestRestart(t *testing.T) {
	var restarted string
	var mu sync.Mutex

	client := httpsClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/aaa/restart" && r.Method == http.MethodPost {
			mu.Lock()
			restarted = "aaa"
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	if err := client.Restart(context.Background(), "aaa"); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if restarted != "aaa" {
		t.Error("Restart did not reach the API")
	}
}

// The daemon serves top as a GET returning the table directly; the mailcow
// service serves it as a POST and wraps it in "msg".
func TestTopSpeaksBothDialects(t *testing.T) {
	const initCmd = "php -c /usr/local/etc/php -f /web/inc/init_db.inc.php"
	processes := [][]string{
		{"root", "1", "0", "php-fpm: master process"},
		{"root", "42", "1", initCmd},
	}

	t.Run("mailcow", func(t *testing.T) {
		client := httpsClient(t, jsonHandler(t, map[string]any{
			"POST /containers/aaa/top": map[string]any{
				"msg": map[string]any{"Processes": processes},
			},
		}))
		assertFindsInitDB(t, client, initCmd)
	})

	t.Run("engine", func(t *testing.T) {
		client, _ := socketClient(t, jsonHandler(t, map[string]any{
			"GET /containers/aaa/top": map[string]any{
				"Titles":    []string{"UID", "PID", "PPID", "CMD"},
				"Processes": processes,
			},
		}))
		assertFindsInitDB(t, client, initCmd)
	})
}

// Restarting php-fpm while it initialises the database would leave the schema
// half-written, so the supervisor checks the process list first.
func assertFindsInitDB(t *testing.T, client *Client, initCmd string) {
	t.Helper()

	running, err := client.Running(context.Background(), "aaa", initCmd)
	if err != nil {
		t.Fatalf("Running: %v", err)
	}
	if !running {
		t.Error("Running should have found the initialiser")
	}

	running, err = client.Running(context.Background(), "aaa", "something else")
	if err != nil {
		t.Fatalf("Running: %v", err)
	}
	if running {
		t.Error("Running matched a process that is not there")
	}
}

func TestReachable(t *testing.T) {
	t.Run("socket", func(t *testing.T) {
		client, socket := socketClient(t, jsonHandler(t, nil))
		if !client.Reachable(context.Background()) {
			t.Error("Reachable() = false for a live socket")
		}

		// Removing the socket is how the daemon going away looks from here.
		if err := os.Remove(socket); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if client.Reachable(context.Background()) {
			t.Error("Reachable() = true after the socket disappeared")
		}
	})

	t.Run("tcp", func(t *testing.T) {
		client := httpsClient(t, jsonHandler(t, nil))
		if !client.Reachable(context.Background()) {
			t.Error("Reachable() = false for a live server")
		}

		unreachable, err := New(Options{BaseURL: "https://127.0.0.1:1"})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if unreachable.Reachable(context.Background()) {
			t.Error("Reachable() = true for a closed port")
		}
	})
}

func TestAPIErrorsAreReported(t *testing.T) {
	client := httpsClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	if _, err := client.List(context.Background()); err == nil {
		t.Error("a 500 should be reported as an error")
	}
}

func TestDialectString(t *testing.T) {
	tests := map[Dialect]string{
		DialectAuto:    "auto",
		DialectMailcow: "mailcow",
		DialectEngine:  "engine",
		Dialect(9):     "invalid",
	}
	for dialect, want := range tests {
		if got := dialect.String(); got != want {
			t.Errorf("Dialect(%d).String() = %q, want %q", dialect, got, want)
		}
	}
}
