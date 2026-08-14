// Package config reads the watchdog's runtime configuration from the
// environment.
//
// The variable names, their defaults and their truthiness rules mirror the
// original watchdog.sh so that the Go binary is a drop-in replacement inside an
// unmodified mailcow docker-compose stack. Everything the shell script derived
// implicitly (socket paths, Redis endpoint, dockerapi base URL) is derived here
// once, at startup, instead of being re-assembled in every check.
package config

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Defaults for the check thresholds. mailcow's docker-compose.yml passes all of
// these explicitly, so these values only apply when the watchdog is started
// outside the compose stack. They mirror the compose defaults.
const (
	defaultExternalThreshold      = 1
	defaultNginxThreshold         = 5
	defaultUnboundThreshold       = 5
	defaultRedisThreshold         = 5
	defaultMySQLThreshold         = 5
	defaultMySQLReplThreshold     = 1
	defaultSOGoThreshold          = 3
	defaultPostfixThreshold       = 8
	defaultPostfixTLSPolThreshold = 8
	defaultClamdThreshold         = 15
	defaultDovecotThreshold       = 12
	defaultDovecotReplThreshold   = 20
	defaultPHPFPMThreshold        = 5
	defaultRatelimitThreshold     = 1
	defaultMailqThreshold         = 20
	defaultFail2banThreshold      = 1
	defaultACMEThreshold          = 1
	defaultRspamdThreshold        = 5
	defaultOlefyThreshold         = 5

	// CertThreshold is not configurable in mailcow; watchdog.sh hard-coded it.
	CertThreshold = 7
)

// defaultMetricsListen is where the observability endpoint binds.
//
// It sits deliberately outside 9100-9999: that range is the Prometheus project's
// exporter registry and is fully allocated — 9099 itself belongs to the SQL
// exporter. The wiki's advice for an application's own exporter is to stay out of
// the registry, and 9393 also avoids every port mailcow uses internally (8081,
// 8642, 9000-9002, 9900, 10001, 10055, 11332-11334, 20000).
const defaultMetricsListen = ":9393"

// Config is the fully resolved runtime configuration.
type Config struct {
	// Enabled mirrors USE_WATCHDOG. When false the process idles instead of
	// exiting, so docker-compose does not treat it as a crash loop.
	Enabled bool

	// Verbose mirrors WATCHDOG_VERBOSE: it makes probe transcripts part of the
	// log output rather than only of the notification body.
	Verbose bool

	// SettleDelay is the grace period before the first probe, giving the rest
	// of the stack time to come up. watchdog.sh counted down from 30.
	SettleDelay time.Duration

	Mailcow  Mailcow
	DB       DB
	Redis    Redis
	Docker   Docker
	Notify   Notify
	Checks   Checks
	Log      Log
	Metrics  Metrics
	MailqDir string
}

// Mailcow holds the stack identity used for hostnames, HELO and label matching.
type Mailcow struct {
	Hostname       string // MAILCOW_HOSTNAME
	ComposeProject string // COMPOSE_PROJECT_NAME
	IPv4Network    string // IPV4_NETWORK, e.g. "172.22.1"
	IPv6Network    string // IPV6_NETWORK, e.g. "fd4d:6169:6c63:6f77::/64"
}

// DB describes how to reach the local MariaDB.
type DB struct {
	Socket   string // DBSOCKET, the shared mysqld.sock volume
	User     string // DBUSER
	Password string // DBPASS
	Name     string // DBNAME
	Root     string // DBROOT, only needed for the replication status query
}

// DSN renders a go-sql-driver DSN for the given user against the unix socket.
// TLS is disabled to match client.cnf, which set `ssl = false` because the
// connection never leaves the container's network namespace.
func (d DB) DSN(user, password, database string) string {
	return fmt.Sprintf("%s:%s@unix(%s)/%s?tls=false&parseTime=true&timeout=5s&readTimeout=10s",
		user, password, d.Socket, database)
}

// AppDSN is the DSN for the unprivileged mailcow application user.
func (d DB) AppDSN() string { return d.DSN(d.User, d.Password, d.Name) }

// RootDSN is the DSN used for replication status, which needs REPLICATION
// CLIENT rights. It intentionally selects no database.
func (d DB) RootDSN() string { return d.DSN("root", d.Root, "") }

// Redis describes the Redis endpoint. When REDIS_SLAVEOF_IP is set, mailcow runs
// Redis in replication and the local instance is read-only, so every client must
// talk to the primary. watchdog.sh honoured this only for some of its calls.
type Redis struct {
	Addr     string // host:port of the instance to write to
	Password string // REDISPASS
	// LocalAddr is the container-local instance, which the redis check probes
	// even when writes go to a remote primary.
	LocalAddr string
}

// Docker describes how container identities and addresses are resolved.
type Docker struct {
	// BaseURL is the endpoint. It defaults to the mailcow dockerapi service,
	// which serves a self-signed certificate over HTTPS, but may also be a
	// socket path such as unix:///var/run/docker.sock to address the Docker
	// daemon directly.
	BaseURL string
	// Dialect is DOCKER_API_DIALECT: auto, mailcow or engine. Empty means the
	// URL scheme decides.
	Dialect string
	// UseAPI mirrors IP_BY_DOCKER_API: when false, container addresses come from
	// the compose network's DNS aliases instead of the API.
	UseAPI bool
}

// Log configures the structured logger.
type Log struct {
	Level  string // LOG_LEVEL: debug|info|warn|error
	Format string // LOG_FORMAT: json|text
}

// Metrics configures the observability endpoint serving /metrics, /healthz and
// /readyz. An empty Listen disables the server entirely.
type Metrics struct {
	Listen string // WATCHDOG_METRICS_LISTEN, e.g. ":9393"
}

// Notify configures alerting.
type Notify struct {
	Emails      []string // WATCHDOG_NOTIFY_EMAIL, comma separated
	Webhook     string   // WATCHDOG_NOTIFY_WEBHOOK
	WebhookBody string   // WATCHDOG_NOTIFY_WEBHOOK_BODY, a JSON template
	Subject     string   // WATCHDOG_SUBJECT
	OnStart     bool     // WATCHDOG_NOTIFY_START
	OnBan       bool     // WATCHDOG_NOTIFY_BAN
	// From is the envelope sender, watchdog@<MAILCOW_HOSTNAME>.
	From string
	// HELO is the name announced to the recipient's MX.
	HELO string
}

// Enabled reports whether any notification channel is configured. When it is
// false the watchdog still restarts containers, it just stays quiet about it.
func (n Notify) Enabled() bool { return len(n.Emails) > 0 || n.Webhook != "" }

// Checks holds per-check enablement and thresholds. A threshold is the number of
// accumulated error points at which the check declares its service dead.
type Checks struct {
	External     CheckSpec
	Nginx        CheckSpec
	Unbound      CheckSpec
	Redis        CheckSpec
	MySQL        CheckSpec
	MySQLRepl    CheckSpec
	SOGo         CheckSpec
	Postfix      CheckSpec
	PostfixTLSPo CheckSpec
	Clamd        CheckSpec
	Dovecot      CheckSpec
	DovecotRepl  CheckSpec
	Cert         CheckSpec
	PHPFPM       CheckSpec
	Ratelimit    CheckSpec
	Mailq        CheckSpec
	Fail2ban     CheckSpec
	ACME         CheckSpec
	Rspamd       CheckSpec
	Olefy        CheckSpec

	// MailqCritical is the deferred-queue size above which mailq reports an
	// error point (MAILQ_CRIT).
	MailqCritical int
}

// CheckSpec is the per-check knob pair.
type CheckSpec struct {
	Enabled   bool
	Threshold int
}

// All returns every check keyed by the name it reports under, for validation
// and for wiring up the runner registry. Use sortedNames when the iteration
// order has to be stable.
func (c Checks) All() map[string]CheckSpec {
	return map[string]CheckSpec{
		"external":       c.External,
		"nginx":          c.Nginx,
		"unbound":        c.Unbound,
		"redis":          c.Redis,
		"mysql":          c.MySQL,
		"mysql-repl":     c.MySQLRepl,
		"sogo":           c.SOGo,
		"postfix":        c.Postfix,
		"postfix-tlspol": c.PostfixTLSPo,
		"clamd":          c.Clamd,
		"dovecot":        c.Dovecot,
		"dovecot-repl":   c.DovecotRepl,
		"cert":           c.Cert,
		"php-fpm":        c.PHPFPM,
		"ratelimit":      c.Ratelimit,
		"mailq":          c.Mailq,
		"fail2ban":       c.Fail2ban,
		"acme":           c.ACME,
		"rspamd":         c.Rspamd,
		"olefy":          c.Olefy,
	}
}

// mailqSpoolDir is where the postfix spool volume is mounted into the watchdog.
const mailqSpoolDir = "/var/spool/postfix/deferred"

// sortedNames returns the map's keys in a stable order so that validation
// errors name the same check on every run.
func sortedNames(m map[string]CheckSpec) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// validate reports the first configuration problem that would make the watchdog
// misbehave silently. Missing credentials are fatal because every check would
// otherwise fail for the same uninteresting reason.
func (c *Config) validate() error {
	if c.Mailcow.Hostname == "" {
		return fmt.Errorf("MAILCOW_HOSTNAME is not set")
	}
	if c.Mailcow.ComposeProject == "" {
		return fmt.Errorf("COMPOSE_PROJECT_NAME is not set")
	}
	if c.DB.User == "" || c.DB.Password == "" || c.DB.Name == "" {
		return fmt.Errorf("DBUSER, DBPASS and DBNAME must all be set")
	}
	if c.Checks.MySQLRepl.Enabled && c.DB.Root == "" {
		return fmt.Errorf("DBROOT must be set when WATCHDOG_MYSQL_REPLICATION_CHECKS is enabled")
	}
	switch c.Docker.Dialect {
	case "", "auto", "mailcow", "engine", "docker":
	default:
		return fmt.Errorf("DOCKER_API_DIALECT must be auto, mailcow or engine (got %q)", c.Docker.Dialect)
	}
	if scheme, _, ok := strings.Cut(c.Docker.BaseURL, ":"); ok {
		switch scheme {
		case "https", "http", "unix":
		default:
			return fmt.Errorf("DOCKER_API_URL must use https:// or unix:// (got %q)", c.Docker.BaseURL)
		}
	}
	if c.Notify.Webhook != "" {
		if _, err := url.Parse(c.Notify.Webhook); err != nil {
			return fmt.Errorf("WATCHDOG_NOTIFY_WEBHOOK is not a valid URL: %w", err)
		}
		if c.Notify.WebhookBody == "" {
			return fmt.Errorf("WATCHDOG_NOTIFY_WEBHOOK is set but WATCHDOG_NOTIFY_WEBHOOK_BODY is empty")
		}
	}
	for _, addr := range c.Notify.Emails {
		if !strings.Contains(addr, "@") {
			return fmt.Errorf("WATCHDOG_NOTIFY_EMAIL contains %q, which is not an address", addr)
		}
	}
	// A threshold of zero would make a check declare its service dead before it
	// ever probed anything, so the watchdog would restart the container in a
	// tight loop. watchdog.sh had the same hole and no guard against it.
	for _, name := range sortedNames(c.Checks.All()) {
		spec := c.Checks.All()[name]
		if spec.Enabled && spec.Threshold < 1 {
			return fmt.Errorf("threshold for check %q must be at least 1 (got %d)", name, spec.Threshold)
		}
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("LOG_LEVEL must be one of debug, info, warn, error (got %q)", c.Log.Level)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("LOG_FORMAT must be json or text (got %q)", c.Log.Format)
	}
	return nil
}
