package config

import (
	"strings"
	"testing"
	"time"
)

// minimal is the smallest environment that passes validation. Individual tests
// clone it and override the keys they care about.
func minimal() map[string]string {
	return map[string]string{
		"MAILCOW_HOSTNAME":     "mail.example.org",
		"COMPOSE_PROJECT_NAME": "mailcowdockerized",
		"DBUSER":               "mailcow",
		"DBPASS":               "secret",
		"DBNAME":               "mailcow",
	}
}

func lookupFrom(m map[string]string) Lookup {
	return func(key string) (string, bool) {
		v, ok := m[key]
		return v, ok
	}
}

func loadWith(t *testing.T, overrides map[string]string) *Config {
	t.Helper()
	envs := minimal()
	for k, v := range overrides {
		envs[k] = v
	}
	cfg, err := Load(lookupFrom(envs))
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	return cfg
}

func TestLoadDefaults(t *testing.T) {
	cfg := loadWith(t, nil)

	if !cfg.Enabled {
		t.Error("watchdog should be enabled when USE_WATCHDOG is unset")
	}
	if cfg.SettleDelay != 30*time.Second {
		t.Errorf("SettleDelay = %v, want 30s", cfg.SettleDelay)
	}
	if got, want := cfg.Redis.Addr, "redis:6379"; got != want {
		t.Errorf("Redis.Addr = %q, want %q", got, want)
	}
	if got, want := cfg.Docker.BaseURL, "https://dockerapi.mailcowdockerized_mailcow-network"; got != want {
		t.Errorf("Docker.BaseURL = %q, want %q", got, want)
	}
	if cfg.Docker.UseAPI {
		t.Error("IP_BY_DOCKER_API should default to DNS resolution")
	}
	if got, want := cfg.Notify.From, "watchdog@mail.example.org"; got != want {
		t.Errorf("Notify.From = %q, want %q", got, want)
	}
	if cfg.Notify.Enabled() {
		t.Error("notifications should be off when neither email nor webhook is configured")
	}
	if got, want := cfg.Checks.MailqCritical, 30; got != want {
		t.Errorf("MailqCritical = %d, want %d", got, want)
	}
	if got, want := cfg.Checks.Cert.Threshold, CertThreshold; got != want {
		t.Errorf("Cert.Threshold = %d, want %d", got, want)
	}
}

func TestUseWatchdogOff(t *testing.T) {
	for _, v := range []string{"n", "N", "no", "NO", " no "} {
		cfg := loadWith(t, map[string]string{"USE_WATCHDOG": v})
		if cfg.Enabled {
			t.Errorf("USE_WATCHDOG=%q should disable the watchdog", v)
		}
	}
	for _, v := range []string{"y", "yes", "", "anything"} {
		cfg := loadWith(t, map[string]string{"USE_WATCHDOG": v})
		if !cfg.Enabled {
			t.Errorf("USE_WATCHDOG=%q should leave the watchdog enabled", v)
		}
	}
}

// The SKIP_* variables are inverted: mailcow sets them to "n" to request that
// the check runs. Anything else disables it.
func TestSkipVariablesAreInverted(t *testing.T) {
	tests := []struct {
		key   string
		get   func(Checks) CheckSpec
		value string
		want  bool
	}{
		{"SKIP_SOGO", func(c Checks) CheckSpec { return c.SOGo }, "n", true},
		{"SKIP_SOGO", func(c Checks) CheckSpec { return c.SOGo }, "y", false},
		{"SKIP_CLAMD", func(c Checks) CheckSpec { return c.Clamd }, "no", true},
		{"SKIP_CLAMD", func(c Checks) CheckSpec { return c.Clamd }, "yes", false},
		{"SKIP_OLEFY", func(c Checks) CheckSpec { return c.Olefy }, "n", true},
		{"SKIP_OLEFY", func(c Checks) CheckSpec { return c.Olefy }, "1", false},
	}
	for _, tc := range tests {
		cfg := loadWith(t, map[string]string{tc.key: tc.value})
		if got := tc.get(cfg.Checks).Enabled; got != tc.want {
			t.Errorf("%s=%q: enabled = %v, want %v", tc.key, tc.value, got, tc.want)
		}
	}
}

// The endpoint may be the mailcow dockerapi over HTTPS or the Docker daemon's
// own socket; the scheme is what tells the client which.
func TestDockerEndpoint(t *testing.T) {
	cfg := loadWith(t, nil)
	if got, want := cfg.Docker.BaseURL, "https://dockerapi.mailcowdockerized_mailcow-network"; got != want {
		t.Errorf("Docker.BaseURL = %q, want %q", got, want)
	}
	if cfg.Docker.Dialect != "auto" {
		t.Errorf("Docker.Dialect = %q, want auto", cfg.Docker.Dialect)
	}

	cfg = loadWith(t, map[string]string{"DOCKER_API_URL": "unix:///var/run/docker.sock"})
	if got, want := cfg.Docker.BaseURL, "unix:///var/run/docker.sock"; got != want {
		t.Errorf("Docker.BaseURL = %q, want %q", got, want)
	}

	cfg = loadWith(t, map[string]string{"DOCKER_API_DIALECT": "ENGINE"})
	if cfg.Docker.Dialect != "engine" {
		t.Errorf("Docker.Dialect = %q, want engine", cfg.Docker.Dialect)
	}
}

func TestUnboundAndDockerAPIFlags(t *testing.T) {
	if cfg := loadWith(t, map[string]string{"CHECK_UNBOUND": "0"}); cfg.Checks.Unbound.Enabled {
		t.Error("CHECK_UNBOUND=0 should disable the unbound check")
	}
	if cfg := loadWith(t, nil); !cfg.Checks.Unbound.Enabled {
		t.Error("unbound should be checked by default")
	}
	if cfg := loadWith(t, map[string]string{"IP_BY_DOCKER_API": "1"}); !cfg.Docker.UseAPI {
		t.Error("IP_BY_DOCKER_API=1 should switch to API resolution")
	}
}

// A Redis replica is read-only, so every write must go to the primary. The
// local instance still needs an address of its own for the redis check.
func TestRedisSlaveOf(t *testing.T) {
	cfg := loadWith(t, map[string]string{
		"REDIS_SLAVEOF_IP":   "10.0.0.5",
		"REDIS_SLAVEOF_PORT": "6380",
		"REDISPASS":          "hunter2",
	})
	if got, want := cfg.Redis.Addr, "10.0.0.5:6380"; got != want {
		t.Errorf("Redis.Addr = %q, want %q", got, want)
	}
	if got, want := cfg.Redis.LocalAddr, "redis:6379"; got != want {
		t.Errorf("Redis.LocalAddr = %q, want %q", got, want)
	}
	if got, want := cfg.Redis.Password, "hunter2"; got != want {
		t.Errorf("Redis.Password = %q, want %q", got, want)
	}
}

func TestRedisSlaveOfDefaultPort(t *testing.T) {
	cfg := loadWith(t, map[string]string{"REDIS_SLAVEOF_IP": "10.0.0.5"})
	if got, want := cfg.Redis.Addr, "10.0.0.5:6379"; got != want {
		t.Errorf("Redis.Addr = %q, want %q", got, want)
	}
}

func TestSplitAddresses(t *testing.T) {
	tests := []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{`"admin@example.org"`, []string{"admin@example.org"}},
		{"a@example.org,b@example.org", []string{"a@example.org", "b@example.org"}},
		{" a@example.org , b@example.org ", []string{"a@example.org", "b@example.org"}},
		{"a@example.org,,b@example.org", []string{"a@example.org", "b@example.org"}},
		{`"a@example.org","b@example.org"`, []string{"a@example.org", "b@example.org"}},
	}
	for _, tc := range tests {
		got := splitAddresses(tc.raw)
		if len(got) != len(tc.want) {
			t.Errorf("splitAddresses(%q) = %v, want %v", tc.raw, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitAddresses(%q)[%d] = %q, want %q", tc.raw, i, got[i], tc.want[i])
			}
		}
	}
}

// DEV_MODE is the shell script's `set -x`; the structured equivalent is debug
// logging, but an explicit LOG_LEVEL must still win.
func TestDevModeMapsToDebugLogging(t *testing.T) {
	cfg := loadWith(t, map[string]string{"DEV_MODE": "y"})
	if cfg.Log.Level != "debug" || cfg.Log.Format != "text" {
		t.Errorf("DEV_MODE=y: log = %+v, want debug/text", cfg.Log)
	}

	cfg = loadWith(t, map[string]string{"DEV_MODE": "n"})
	if cfg.Log.Level != "info" || cfg.Log.Format != "json" {
		t.Errorf("DEV_MODE=n: log = %+v, want info/json", cfg.Log)
	}

	cfg = loadWith(t, map[string]string{"DEV_MODE": "y", "LOG_LEVEL": "warn"})
	if cfg.Log.Level != "warn" {
		t.Errorf("explicit LOG_LEVEL should win, got %q", cfg.Log.Level)
	}
}

func TestDSN(t *testing.T) {
	cfg := loadWith(t, map[string]string{"DBROOT": "rootpw"})

	app := cfg.DB.AppDSN()
	if !strings.HasPrefix(app, "mailcow:secret@unix(/var/run/mysqld/mysqld.sock)/mailcow?") {
		t.Errorf("AppDSN = %q", app)
	}
	// client.cnf disabled TLS because the socket never leaves the container.
	if !strings.Contains(app, "tls=false") {
		t.Errorf("AppDSN should disable TLS, got %q", app)
	}
	root := cfg.DB.RootDSN()
	if !strings.HasPrefix(root, "root:rootpw@unix(/var/run/mysqld/mysqld.sock)/?") {
		t.Errorf("RootDSN = %q", root)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]string
		remove    []string
		want      string
	}{
		{
			name:   "missing hostname",
			remove: []string{"MAILCOW_HOSTNAME"},
			want:   "MAILCOW_HOSTNAME",
		},
		{
			name:   "missing compose project",
			remove: []string{"COMPOSE_PROJECT_NAME"},
			want:   "COMPOSE_PROJECT_NAME",
		},
		{
			name:   "missing db credentials",
			remove: []string{"DBPASS"},
			want:   "DBUSER, DBPASS and DBNAME",
		},
		{
			name:      "replication without root password",
			overrides: map[string]string{"WATCHDOG_MYSQL_REPLICATION_CHECKS": "y"},
			want:      "DBROOT",
		},
		{
			name:      "webhook without body",
			overrides: map[string]string{"WATCHDOG_NOTIFY_WEBHOOK": "https://hooks.example.org/x"},
			want:      "WATCHDOG_NOTIFY_WEBHOOK_BODY",
		},
		{
			name:      "recipient without at sign",
			overrides: map[string]string{"WATCHDOG_NOTIFY_EMAIL": "not-an-address"},
			want:      "not an address",
		},
		{
			name:      "non numeric threshold",
			overrides: map[string]string{"NGINX_THRESHOLD": "many"},
			want:      "NGINX_THRESHOLD must be an integer",
		},
		{
			name:      "negative threshold",
			overrides: map[string]string{"NGINX_THRESHOLD": "-1"},
			want:      "must not be negative",
		},
		{
			// A zero threshold would declare the service dead before the first
			// probe and restart the container in a loop.
			name:      "zero threshold",
			overrides: map[string]string{"NGINX_THRESHOLD": "0"},
			want:      `threshold for check "nginx"`,
		},
		{
			name:      "bad docker dialect",
			overrides: map[string]string{"DOCKER_API_DIALECT": "kubernetes"},
			want:      "DOCKER_API_DIALECT",
		},
		{
			name:      "bad docker scheme",
			overrides: map[string]string{"DOCKER_API_URL": "tcp://dockerapi:2375"},
			want:      "DOCKER_API_URL must use https:// or unix://",
		},
		{
			name:      "bad log level",
			overrides: map[string]string{"LOG_LEVEL": "chatty"},
			want:      "LOG_LEVEL",
		},
		{
			name:      "bad log format",
			overrides: map[string]string{"LOG_FORMAT": "xml"},
			want:      "LOG_FORMAT",
		},
		{
			name:      "bad settle delay",
			overrides: map[string]string{"WATCHDOG_SETTLE_DELAY": "half a minute"},
			want:      "WATCHDOG_SETTLE_DELAY",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			envs := minimal()
			for _, k := range tc.remove {
				delete(envs, k)
			}
			for k, v := range tc.overrides {
				envs[k] = v
			}
			_, err := Load(lookupFrom(envs))
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A disabled check may keep a nonsensical threshold; it never runs.
func TestZeroThresholdOnDisabledCheckIsFine(t *testing.T) {
	loadWith(t, map[string]string{
		"SKIP_CLAMD":      "y",
		"CLAMD_THRESHOLD": "0",
	})
}

func TestAllCoversEveryCheck(t *testing.T) {
	cfg := loadWith(t, nil)
	all := cfg.Checks.All()
	// One entry per check function in the original watchdog.sh.
	if got, want := len(all), 20; got != want {
		t.Errorf("Checks.All() has %d entries, want %d", got, want)
	}
	for name, spec := range all {
		if spec.Enabled && spec.Threshold < 1 {
			t.Errorf("check %q is enabled with threshold %d", name, spec.Threshold)
		}
	}
}
