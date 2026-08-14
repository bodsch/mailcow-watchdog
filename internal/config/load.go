package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Lookup resolves an environment variable. os.LookupEnv satisfies it; tests
// substitute a map so that Load can be exercised without touching the process
// environment.
type Lookup func(key string) (string, bool)

// EnvLookup reads from the process environment.
func EnvLookup(key string) (string, bool) { return os.LookupEnv(key) }

// Load builds a Config from the environment and validates it.
func Load(look Lookup) (*Config, error) {
	if look == nil {
		look = EnvLookup
	}
	e := env{look: look}

	cfg := &Config{
		// USE_WATCHDOG is the main switch. watchdog.sh treated only an
		// explicit n/no as "off"; anything else, including unset, means on.
		Enabled:     !isNo(e.str("USE_WATCHDOG", "y")),
		Verbose:     isYes(e.str("WATCHDOG_VERBOSE", "n")),
		SettleDelay: e.duration("WATCHDOG_SETTLE_DELAY", 30*time.Second),
		MailqDir:    e.str("MAILQ_SPOOL_DIR", mailqSpoolDir),

		Mailcow: Mailcow{
			Hostname:       e.str("MAILCOW_HOSTNAME", ""),
			ComposeProject: e.str("COMPOSE_PROJECT_NAME", ""),
			IPv4Network:    e.str("IPV4_NETWORK", ""),
			IPv6Network:    e.str("IPV6_NETWORK", ""),
		},

		DB: DB{
			Socket:   e.str("DBSOCKET", "/var/run/mysqld/mysqld.sock"),
			User:     e.str("DBUSER", ""),
			Password: e.str("DBPASS", ""),
			Name:     e.str("DBNAME", ""),
			Root:     e.str("DBROOT", ""),
		},
	}

	cfg.Redis = loadRedis(&e)
	cfg.Docker = loadDocker(&e, cfg.Mailcow.ComposeProject)
	cfg.Notify = loadNotify(&e, cfg.Mailcow.Hostname)
	cfg.Checks = loadChecks(&e)
	cfg.Log = loadLog(&e, cfg.Verbose)
	cfg.Obs = Obs{Listen: e.str("WATCHDOG_METRICS_LISTEN", DefaultObsListen)}

	if err := e.err(); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// loadRedis resolves the write endpoint. mailcow points REDIS_SLAVEOF_IP at the
// replication primary; the local instance is then read-only and must not be
// written to, but it still has to be health-checked.
func loadRedis(e *env) Redis {
	const localAddr = "redis:6379"

	addr := localAddr
	if ip := e.str("REDIS_SLAVEOF_IP", ""); ip != "" {
		port := e.str("REDIS_SLAVEOF_PORT", "6379")
		addr = net.JoinHostPort(ip, port)
	}
	return Redis{
		Addr:      addr,
		Password:  e.str("REDISPASS", ""),
		LocalAddr: localAddr,
	}
}

// loadDocker assembles the API endpoint. The mailcow dockerapi service is only
// reachable under the per-project network name, which is why the compose project
// is part of the default hostname. Operators who would rather not run that
// container can point DOCKER_API_URL at unix:///var/run/docker.sock instead.
func loadDocker(e *env, project string) Docker {
	base := e.str("DOCKER_API_URL", "")
	if base == "" && project != "" {
		base = fmt.Sprintf("https://dockerapi.%s_mailcow-network", project)
	}
	return Docker{
		BaseURL: base,
		Dialect: strings.ToLower(e.str("DOCKER_API_DIALECT", "auto")),
		UseAPI:  e.int("IP_BY_DOCKER_API", 0) != 0,
	}
}

func loadNotify(e *env, hostname string) Notify {
	return Notify{
		// watchdog.sh stripped a leading and trailing double quote here because
		// mailcow.conf values are frequently quoted by hand.
		Emails:      splitAddresses(e.str("WATCHDOG_NOTIFY_EMAIL", "")),
		Webhook:     strings.TrimSpace(e.str("WATCHDOG_NOTIFY_WEBHOOK", "")),
		WebhookBody: e.str("WATCHDOG_NOTIFY_WEBHOOK_BODY", ""),
		Subject:     e.str("WATCHDOG_SUBJECT", "Watchdog ALERT"),
		OnStart:     isYes(e.str("WATCHDOG_NOTIFY_START", "y")),
		OnBan:       isYes(e.str("WATCHDOG_NOTIFY_BAN", "n")),
		From:        "watchdog@" + hostname,
		HELO:        hostname,
	}
}

func loadChecks(e *env) Checks {
	// The SKIP_* variables are inverted: mailcow sets them to "n" to mean "run
	// this check". CHECK_UNBOUND is a plain 0/1 flag instead.
	return Checks{
		External:     CheckSpec{isYes(e.str("WATCHDOG_EXTERNAL_CHECKS", "n")), e.int("EXTERNAL_CHECKS_THRESHOLD", defaultExternalThreshold)},
		Nginx:        CheckSpec{true, e.int("NGINX_THRESHOLD", defaultNginxThreshold)},
		Unbound:      CheckSpec{e.int("CHECK_UNBOUND", 1) == 1, e.int("UNBOUND_THRESHOLD", defaultUnboundThreshold)},
		Redis:        CheckSpec{true, e.int("REDIS_THRESHOLD", defaultRedisThreshold)},
		MySQL:        CheckSpec{true, e.int("MYSQL_THRESHOLD", defaultMySQLThreshold)},
		MySQLRepl:    CheckSpec{isYes(e.str("WATCHDOG_MYSQL_REPLICATION_CHECKS", "n")), e.int("MYSQL_REPLICATION_THRESHOLD", defaultMySQLReplThreshold)},
		SOGo:         CheckSpec{isNo(e.str("SKIP_SOGO", "n")), e.int("SOGO_THRESHOLD", defaultSOGoThreshold)},
		Postfix:      CheckSpec{true, e.int("POSTFIX_THRESHOLD", defaultPostfixThreshold)},
		PostfixTLSPo: CheckSpec{true, e.int("POSTFIX_TLSPOL_THRESHOLD", defaultPostfixTLSPolThreshold)},
		Clamd:        CheckSpec{isNo(e.str("SKIP_CLAMD", "n")), e.int("CLAMD_THRESHOLD", defaultClamdThreshold)},
		Dovecot:      CheckSpec{true, e.int("DOVECOT_THRESHOLD", defaultDovecotThreshold)},
		DovecotRepl:  CheckSpec{true, e.int("DOVECOT_REPL_THRESHOLD", defaultDovecotReplThreshold)},
		Cert:         CheckSpec{true, CertThreshold},
		PHPFPM:       CheckSpec{true, e.int("PHPFPM_THRESHOLD", defaultPHPFPMThreshold)},
		Ratelimit:    CheckSpec{true, e.int("RATELIMIT_THRESHOLD", defaultRatelimitThreshold)},
		Mailq:        CheckSpec{true, e.int("MAILQ_THRESHOLD", defaultMailqThreshold)},
		Fail2ban:     CheckSpec{true, e.int("FAIL2BAN_THRESHOLD", defaultFail2banThreshold)},
		ACME:         CheckSpec{true, e.int("ACME_THRESHOLD", defaultACMEThreshold)},
		Rspamd:       CheckSpec{true, e.int("RSPAMD_THRESHOLD", defaultRspamdThreshold)},
		Olefy:        CheckSpec{isNo(e.str("SKIP_OLEFY", "n")), e.int("OLEFY_THRESHOLD", defaultOlefyThreshold)},

		MailqCritical: e.int("MAILQ_CRIT", 30),
	}
}

// loadLog maps DEV_MODE and WATCHDOG_VERBOSE onto the log level.
//
// watchdog.sh enabled `set -x` unless DEV_MODE was exactly "n", and
// WATCHDOG_VERBOSE additionally turned on `set -xv` plus the verbose flags of
// smtp-cli and curl. Both amount to "show me what the probes are actually
// doing", which here is debug logging: it puts every probe's transcript in the
// log instead of only in a notification body. An explicit LOG_LEVEL still wins.
func loadLog(e *env, verbose bool) Log {
	level := "info"
	format := "json"

	if !isNo(e.str("DEV_MODE", "n")) {
		level = "debug"
		format = "text"
	}
	if verbose {
		level = "debug"
	}

	return Log{
		Level:  strings.ToLower(e.str("LOG_LEVEL", level)),
		Format: strings.ToLower(e.str("LOG_FORMAT", format)),
	}
}

// splitAddresses parses the comma separated recipient list, tolerating the hand
// written quoting and stray whitespace found in mailcow.conf.
func splitAddresses(raw string) []string {
	raw = strings.Trim(strings.TrimSpace(raw), `"'`)
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// isYes reports whether v is mailcow's affirmative spelling. watchdog.sh used
// the regex ^([yY][eE][sS]|[yY])+$, whose trailing + accidentally also matched
// repetitions like "yy"; only the sensible spellings are accepted here.
func isYes(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "y", "yes":
		return true
	}
	return false
}

// isNo is the negative counterpart of isYes.
func isNo(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "n", "no":
		return true
	}
	return false
}

// env accumulates parse errors so that Load can report every malformed variable
// at once instead of failing on the first one.
type env struct {
	look Lookup
	errs []string
}

func (e *env) str(key, def string) string {
	v, ok := e.look(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

func (e *env) int(key string, def int) int {
	raw, ok := e.look(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		e.errs = append(e.errs, fmt.Sprintf("%s must be an integer (got %q)", key, raw))
		return def
	}
	if n < 0 {
		e.errs = append(e.errs, fmt.Sprintf("%s must not be negative (got %d)", key, n))
		return def
	}
	return n
}

func (e *env) duration(key string, def time.Duration) time.Duration {
	raw, ok := e.look(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		e.errs = append(e.errs, fmt.Sprintf("%s must be a duration such as 30s (got %q)", key, raw))
		return def
	}
	return d
}

func (e *env) err() error {
	if len(e.errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration: %s", strings.Join(e.errs, "; "))
}
