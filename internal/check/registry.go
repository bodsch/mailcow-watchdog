package check

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"bodsch.me/mailcow-watchdog/internal/config"
	"bodsch.me/mailcow-watchdog/internal/probe"
	"bodsch.me/mailcow-watchdog/internal/store"
)

// The compose service names the checks probe. They double as the container names
// the supervisor restarts, because mailcow's compose service keys and its
// container labels agree.
const (
	svcNginx   = "nginx-mailcow"
	svcUnbound = "unbound-mailcow"
	// G101: a compose service name, not a credential.
	svcRedis         = "redis-mailcow" //nolint:gosec
	svcMySQL         = "mysql-mailcow"
	svcSOGo          = "sogo-mailcow"
	svcPostfix       = "postfix-mailcow"
	svcPostfixTLSPol = "postfix-tlspol-mailcow"
	svcClamd         = "clamd-mailcow"
	svcDovecot       = "dovecot-mailcow"
	svcPHPFPM        = "php-fpm-mailcow"
	svcRspamd        = "rspamd-mailcow"
	svcOlefy         = "olefy-mailcow"
)

// rspamdSocket is the normal worker's unix socket, shared into the watchdog
// container by compose. The scan goes over it rather than TCP, which is why the
// rspamd settings probe needs no container address.
const rspamdSocket = "/var/lib/rspamd/rspamd.sock"

// tableCountQuery is the statement the MySQL check runs. It touches the storage
// engines rather than only the connection handler, so a wedged InnoDB shows up.
const tableCountQuery = "SELECT COUNT(*) FROM information_schema.tables"

// InitDBProcess is php-fpm's database migration. The supervisor looks for it in
// the container's process list before restarting: interrupting a migration would
// leave the schema half-written.
const InitDBProcess = "php -c /usr/local/etc/php -f /web/inc/init_db.inc.php"

// PHPFPMService is the one container whose restart is gated on InitDBProcess.
const PHPFPMService = svcPHPFPM

// The sleep windows from watchdog.sh, as the numbers the shell used.
//
// `sleep $(( ( RANDOM % 60 ) + 20 ))` covers 20 to 79 seconds inclusive; clamd
// drew from `RANDOM % 120` and the external checks slept half an hour. The
// jitter is what keeps nineteen checks that all started at the same moment from
// hitting the stack in lockstep.
const (
	originalInterval = 20 * time.Second
	standardJitter   = 59 * time.Second
	clamdJitter      = 119 * time.Second

	originalExternal = 30 * time.Minute
	externalJitter   = 19 * time.Second

	originalCert = 5 * time.Minute
)

// Windows are the four sleep windows the checks use.
type Windows struct {
	Standard Interval
	Clamd    Interval
	External Interval
	Cert     Interval
}

// Intervals derives the sleep windows from the configured lower bound.
//
// The jitter stays the size the shell gave it rather than growing with the
// interval: its job is to spread nineteen checks apart, and a minute of spread
// does that as well at five-minute rounds as it did at twenty-second ones.
// Scaling it instead would turn WATCHDOG_CHECK_INTERVAL=5m into rounds anywhere
// between five and twenty minutes, which is not what asking for five minutes
// should mean.
//
// The two long-running checks are raised to the configured bound but never
// lowered below their own: an operator asking for calmer rounds cannot end up
// with the certificate check running more often than everything else, and one
// asking for busier rounds does not get the external checks — which reach out
// over the public network — every twenty seconds.
//
// A non-positive base means the caller built a Config by hand rather than
// through config.Load. It is treated as the original cadence, because the
// alternative is a zero sleep and nineteen checks in a tight loop.
func Intervals(base time.Duration) Windows {
	if base <= 0 {
		base = originalInterval
	}
	return Windows{
		Standard: Interval{Min: base, Max: base + standardJitter},
		Clamd:    Interval{Min: base, Max: base + clamdJitter},
		External: Interval{Min: max(base, originalExternal), Max: max(base, originalExternal) + externalJitter},
		Cert:     Fixed(max(base, originalCert)),
	}
}

// Deps is everything the checks need in order to be built.
type Deps struct {
	Config *config.Config
	// Resolver maps compose service names to addresses.
	Resolver Resolver
	// Store is the Redis the state-watching checks read from. Under
	// REDIS_SLAVEOF that is the replication primary, because the local instance
	// is read-only.
	Store store.Store
	// LocalStore is the container-local Redis. The redis check probes this one
	// even when everything else talks to a primary elsewhere: its event restarts
	// redis-mailcow, so it has to be the health of that container it measures.
	// When nil, Store is used.
	LocalStore probe.RedisPinger
	// AppDB is connected as the mailcow application user.
	AppDB *sql.DB
	// RootDB is connected as root and is only needed for replication status.
	RootDB *sql.DB
}

// Build returns every enabled check, in a stable order.
func Build(deps Deps) ([]*Check, error) {
	if deps.Config == nil {
		return nil, fmt.Errorf("no configuration supplied")
	}
	if deps.Resolver == nil {
		return nil, fmt.Errorf("no resolver supplied")
	}

	cfg := deps.Config
	at := deps.Resolver.Addr
	window := Intervals(cfg.CheckInterval)

	// Without a replication setup both point at the same instance anyway.
	localRedis := deps.LocalStore
	if localRedis == nil {
		localRedis = deps.Store
	}

	// The order is the order watchdog.sh spawned its agents in, which keeps
	// startup logs comparable between the two implementations.
	all := []*Check{
		{
			Name: "nginx", Service: "Nginx", Event: svcNginx,
			Threshold: cfg.Checks.Nginx.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.NewHTTP("http-8081", at(svcNginx), 8081, "/"),
			},
		},
		{
			Name: "external", Service: "External checks", Event: "external_checks",
			Threshold: cfg.Checks.External.Threshold,
			Interval:  window.External, DeadDelay: time.Minute,
		},
		{
			Name: "mysql-repl", Service: "MySQL/MariaDB replication", Event: "mysql_repl_checks",
			Threshold: cfg.Checks.MySQLRepl.Threshold,
			Interval:  window.Standard, DeadDelay: time.Minute,
			Probes: []probe.Probe{
				probe.NewMySQLReplication("replica-status", deps.RootDB),
			},
		},
		{
			Name: "mysql", Service: "MySQL/MariaDB", Event: svcMySQL,
			Threshold: cfg.Checks.MySQL.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.NewMySQLPing("connect", deps.AppDB),
				probe.NewMySQLQuery("table-count", deps.AppDB, tableCountQuery),
			},
		},
		{
			Name: "redis", Service: "Redis", Event: svcRedis,
			Threshold: cfg.Checks.Redis.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.NewRedisPing("ping", localRedis),
			},
		},
		{
			Name: "php-fpm", Service: "PHP-FPM", Event: svcPHPFPM,
			Threshold: cfg.Checks.PHPFPM.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.NewTCP("fpm-9001", at(svcPHPFPM), 9001, probe.TCPOptions{}),
				probe.NewTCP("fpm-9002", at(svcPHPFPM), 9002, probe.TCPOptions{}),
			},
		},
		{
			Name: "sogo", Service: "SOGo", Event: svcSOGo,
			Threshold: cfg.Checks.SOGo.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.NewHTTP("http-20000", at(svcSOGo), 20000, "/SOGo.index/"),
			},
		},
		{
			Name: "unbound", Service: "Unbound", Event: svcUnbound,
			Threshold: cfg.Checks.Unbound.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.NewDNS("lookup", at(svcUnbound), probe.DNSPort, "stackoverflow.com"),
				// The shell added a literal one point for a DNSSEC failure
				// rather than folding in an exit code.
				probe.Cost(1, probe.NewDNSSEC("dnssec", at(svcUnbound), probe.DNSPort, "com")),
			},
		},
		{
			Name: "clamd", Service: "Clamd", Event: svcClamd,
			Threshold: cfg.Checks.Clamd.Threshold,
			Interval:  window.Clamd, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.NewClamd("ping", at(svcClamd)),
			},
		},
		{
			Name: "postfix", Service: "Postfix", Event: svcPostfix,
			Threshold: cfg.Checks.Postfix.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.NewSMTP("transaction", at(svcPostfix), 589, probe.SMTPOptions{
					HELO: cfg.Mailcow.Hostname,
					From: "watchdog@invalid",
					Commands: []probe.Command{
						{Send: "RCPT TO:watchdog@localhost", Expect: "250"},
						{Send: "DATA"},
						{Send: "."},
					},
				}),
				probe.NewSMTP("starttls", at(svcPostfix), 589, probe.SMTPOptions{
					HELO:     cfg.Mailcow.Hostname,
					StartTLS: true,
				}),
			},
		},
		{
			Name: "mailq", Service: "Mail queue", Event: "mail_queue_status",
			Threshold: cfg.Checks.Mailq.Threshold,
			Interval:  window.Standard, DeadDelay: time.Minute,
			Probes: []probe.Probe{
				probe.Cost(1, probe.NewMailq("deferred", cfg.MailqDir, cfg.Checks.MailqCritical)),
			},
		},
		{
			Name: "postfix-tlspol", Service: "Postfix TLS Policy companion", Event: svcPostfixTLSPol,
			Threshold: cfg.Checks.PostfixTLSPo.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.NewTCP("tlspol-8642", at(svcPostfixTLSPol), 8642, probe.TCPOptions{}),
			},
		},
		{
			Name: "dovecot", Service: "Dovecot", Event: svcDovecot,
			Threshold: cfg.Checks.Dovecot.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				// The LMTP probe expects a rejection: only a working user
				// lookup can answer "User doesn't exist".
				probe.NewSMTP("lmtp-24", at(svcDovecot), 24, probe.SMTPOptions{
					LMTP: true,
					HELO: cfg.Mailcow.Hostname,
					From: "watchdog@invalid",
					Commands: []probe.Command{
						{Send: "RCPT TO:<watchdog@invalid>", Expect: "User doesn't exist"},
					},
				}),
				probe.NewIMAP("imaps-993", at(svcDovecot), 993, probe.IMAPOptions{TLS: true, Expect: "OK "}),
				probe.NewIMAP("imap-143", at(svcDovecot), 143, probe.IMAPOptions{Expect: "OK "}),
				probe.NewTCP("replication-10001", at(svcDovecot), 10001,
					probe.TCPOptions{Expect: "VERSION"}),
				probe.NewTCP("managesieve-4190", at(svcDovecot), 4190,
					probe.TCPOptions{Expect: "Dovecot ready"}),
			},
		},
		{
			Name: "dovecot-repl", Service: "Dovecot replication", Event: "dovecot_repl_checks",
			Threshold: cfg.Checks.DovecotRepl.Threshold,
			Interval:  window.Standard, DeadDelay: time.Minute,
			Probes: []probe.Probe{
				probe.Cost(1, probe.NewRedisFlag("repl-health", deps.Store, "DOVECOT_REPL_HEALTH", "1")),
			},
		},
		{
			Name: "rspamd", Service: "Rspamd", Event: svcRspamd,
			Threshold: cfg.Checks.Rspamd.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.Cost(1, probe.NewRspamd("settings", rspamdSocket)),
				probe.Cost(1, probe.NewMilter("milter", at(svcRspamd), 9900, probe.DefaultTimeout)),
			},
		},
		{
			Name: "ratelimit", Service: "Ratelimit", Event: "ratelimit",
			Threshold: cfg.Checks.Ratelimit.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
		},
		{
			Name: "fail2ban", Service: "Fail2ban", Event: "fail2ban",
			Threshold: cfg.Checks.Fail2ban.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
		},
		{
			// The certificate threshold was hard-coded in the shell, and the
			// check slept a flat five minutes because its notifications are
			// throttled to one a day anyway. WATCHDOG_CHECK_INTERVAL can only
			// stretch that, never shorten it.
			Name: "cert", Service: "Primary certificate expiry check", Event: "certcheck",
			Threshold: config.CertThreshold,
			Interval:  window.Cert, DeadDelay: 5 * time.Minute,
			Probes: []probe.Probe{
				// watchdog.sh asked for "postfix" and "dovecot" here. Those are
				// not the compose service names, so under IP_BY_DOCKER_API the
				// lookup matched nothing and the check reported a permanent
				// false alarm.
				probe.NewSMTP("postfix-cert", at(svcPostfix), 589, probe.SMTPOptions{
					HELO:        cfg.Mailcow.Hostname,
					StartTLS:    true,
					MinCertDays: config.CertThreshold,
				}),
				probe.NewIMAP("dovecot-cert", at(svcDovecot), 993, probe.IMAPOptions{
					TLS:         true,
					MinCertDays: config.CertThreshold,
				}),
			},
		},
		{
			Name: "olefy", Service: "Olefy", Event: svcOlefy,
			Threshold: cfg.Checks.Olefy.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.NewTCP("olefy-10055", at(svcOlefy), 10055, probe.TCPOptions{Send: "PING\n"}),
			},
		},
		{
			Name: "acme", Service: "ACME", Event: "acme-mailcow",
			Threshold: cfg.Checks.ACME.Threshold,
			Interval:  window.Standard, DeadDelay: time.Second,
			Probes: []probe.Probe{
				probe.Cost(1, probe.NewRedisChange("fail-time", deps.Store, "ACME_FAIL_TIME")),
			},
		},
	}

	attachStatefulProbes(all, deps)

	enabled := cfg.Checks.All()
	live := make([]*Check, 0, len(all))
	for _, c := range all {
		spec, known := enabled[c.Name]
		if !known {
			return nil, fmt.Errorf("check %q has no configuration entry", c.Name)
		}
		if !spec.Enabled {
			continue
		}
		if len(c.Probes) == 0 {
			return nil, fmt.Errorf("check %q is enabled but has no probes", c.Name)
		}
		live = append(live, c)
	}
	return live, nil
}

// attachStatefulProbes wires up the three checks whose probes also supply the
// notification body, which needs a reference to the probe itself.
func attachStatefulProbes(all []*Check, deps Deps) {
	for _, c := range all {
		switch c.Name {
		case "ratelimit":
			p := probe.NewRatelimit("rl-log", deps.Store)
			c.Probes = []probe.Probe{probe.Cost(1, p)}
			c.details = p.Details

		case "external":
			guid := guidFunc(deps.AppDB)
			v4 := probe.NewExternal("relay-ipv4", "tcp4", probe.ExternalEndpoint, guid)
			v6 := probe.NewExternal("relay-ipv6", "tcp6", probe.ExternalEndpoint, guid)
			c.Probes = []probe.Probe{probe.Cost(1, v4), probe.Cost(1, v6)}
			// The shell stored the IPv4 body even when it was the IPv6 test that
			// failed; here each family reports its own.
			c.details = func(context.Context) string {
				return joinNonEmpty("\n\n", v4.Details(), v6.Details())
			}

		case "fail2ban":
			p := probe.NewFail2ban("active-bans", deps.Store)
			c.Probes = []probe.Probe{probe.Cost(1, p)}
			c.Bans = p.Fresh
		}
	}
}

// guidFunc reads the installation identifier the external check reports
// upstream. It is looked up per round rather than cached, so a watchdog that
// started before the database was populated still recovers.
func guidFunc(db *sql.DB) probe.GUIDFunc {
	return func(ctx context.Context) (string, error) {
		if db == nil {
			return "", fmt.Errorf("no database handle configured")
		}
		return probe.GUID(ctx, db)
	}
}

func joinNonEmpty(sep string, parts ...string) string {
	var kept []string
	for _, part := range parts {
		if part != "" {
			kept = append(kept, part)
		}
	}
	if len(kept) == 0 {
		return ""
	}
	out := kept[0]
	for _, part := range kept[1:] {
		out += sep + part
	}
	return out
}
