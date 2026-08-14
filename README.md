# mailcow-watchdog

A Go rewrite of the `watchdog.sh` that ships with
[mailcow-dockerized](https://github.com/mailcow/mailcow-dockerized).

It is a **drop-in replacement**: the same environment variables configure it, the
same Redis keys carry its state, and container restarts still go through the
mailcow `dockerapi` service. Swapping the image is enough — `mailcow.conf` needs
no changes.

The original is preserved under `orgiginal/watchdog/` for reference.

---

## Why

The shell version worked, but its structure made three things hard:

- **Efficiency.** Every round forked a Nagios plugin, `dig`, `redis-cli`,
  `mariadb`, `curl` and `jq`. Nineteen check loops did this continuously. All of
  that is now in-process.
- **Code quality.** The nineteen check functions were the same twelve lines of
  error accounting copy-pasted, which is how several of them drifted apart.
- **Testability.** Nothing was testable. The bugs listed below had been in
  production for years because there was no way to notice them.

The runtime image went from Alpine plus ~25 packages — including an `smtp-cli`
downloaded from GitHub at build time over an unpinned URL — to a single static
binary on distroless.

---

## Bugs fixed from the original

These were found while porting. All of them are fixed here; the behaviour is
otherwise unchanged.

| # | Where | Problem |
|---|---|---|
| 1 | all 19 checks | **The self-healing never worked.** `trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1` uses double quotes, so `${err_count}` expanded to `0` when the trap was *installed*. The trap body was literally `[ 0 -gt 1 ] && err_count=-2` — a no-op. The documented "reduce error count by 2 after restarting an unhealthy container" feature did not exist. |
| 2 | `external_checks` | The IPv6 failure branch stored `${CHECK_REPONSE}` (the IPv4 body) instead of `${CHECK_REPONSE6}`, so the IPv6 report was lost. |
| 3 | `cert_checks` | Resolved `postfix` and `dovecot` instead of `postfix-mailcow` / `dovecot-mailcow`. Under `IP_BY_DOCKER_API=1` the exact label match found nothing, returned the placeholder `240.0.0.0`, and the certificate check reported a permanent false alarm. |
| 4 | `dovecot_repl`, `ratelimit`, `acme` | Hard-coded `redis-cli -h redis`, ignoring `REDIS_SLAVEOF_IP`. Only some calls honoured the replication setup. |
| 5 | worker monitor | `sleep 10` sat *inside* the `for` loop over all workers, so one full pass took ~3 minutes instead of 10 seconds. |
| 6 | `notify_error` | The throttle only re-armed when `TTL` returned `-2`. A key with no expiry (`-1`) blocked that notification forever. It was also a read-then-write race. Now a single atomic `SET NX EX`. |
| 7 | webhook | Placeholders were substituted with `sed`, escaping only `/` and `&`. A subject or transcript containing `"`, `\` or a newline produced invalid JSON that the webhook silently rejected. Values are now JSON-escaped. |
| 8 | `rspamd_checks` | Called `usr/bin/curl` without a leading slash; it only worked because the working directory happened to be `/`. |
| 9 | `redis_checks` | Resolved a container IP into `host_ip` and then never used it. |
| 10 | config | A threshold of `0` made a check report its service dead before the first probe, restarting the container in a tight loop. Now rejected at startup. |

### Deliberately *not* "fixed"

- **Nagios exit codes are summed into the error budget**, so a `CRITICAL` costs
  two points and a `WARNING` one. This looks accidental, but the thresholds in
  `mailcow.conf` are calibrated against it. Preserved exactly — see
  `internal/health`.
- **Checks that the shell implemented itself always added exactly one point**,
  regardless of severity. Preserved via the `probe.Cost(1, …)` wrapper, which
  keeps the reported severity honest for logs and metrics while pinning the cost.
- **The health percentage** uses the original's integer arithmetic
  (`((200*c/t)%2) + (100*c/t)`), verified against `bash` output, so the bars in
  the mailcow UI do not shift.
- **`WATCHDOG_LOG` record shapes** are byte-identical, including the message
  sanitiser (`tr '\r\n%&;$"_[]{}-' ' '`) that turns `nginx-mailcow` into
  `nginx mailcow`.
- **The replication query stays `SHOW SLAVE STATUS`.** MariaDB added `REPLICA` as
  a statement synonym in 10.5.1 ([MDEV-20601](https://jira.mariadb.org/browse/MDEV-20601))
  but deliberately left the result columns alone, so `SHOW REPLICA STATUS` still
  returns `Slave_IO_Running`, not `Replica_IO_Running`. Switching the statement
  would buy nothing and would break the check on older installations. The Go
  code's own vocabulary is primary/replica throughout; only the four column
  constants keep MariaDB's spelling, because that is what the server sends.

### One intentional behaviour change

`F2B_RES` is no longer written. It was a private channel between the fail2ban
check's subshell and the main loop — the only way a bash subshell could return
data. New bans now travel in the event itself.

---

## What's new

- **Prometheus metrics** on `:9393/metrics` (`WATCHDOG_METRICS_LISTEN`):
  per-check health and error budget, probe latency histograms and outcome
  counters, restart counters by result, notification outcomes, and a `paused`
  gauge.
- **`/healthz` and `/readyz`.** Liveness deliberately does *not* depend on
  MariaDB or Redis — otherwise a database outage would have the orchestrator kill
  the very thing reporting on it. Readiness stays negative until both are up.
- **Structured logging** via `log/slog` (`LOG_LEVEL`, `LOG_FORMAT`). `DEV_MODE`
  maps to debug + text, the shell's `set -x` equivalent.
- **Graceful shutdown** on SIGINT/SIGTERM.

---

## Architecture

```
cmd/watchdog/          startup sequence, wiring, shutdown
internal/config/       the mailcow.conf environment, typed and validated
internal/health/       the error-budget state machine (the shell's err_count)
internal/probe/        native replacements for the Nagios plugins
internal/check/        probes composed into the 20 monitored services
internal/supervisor/   runners, the pause gate, the event bus, the actions
internal/store/        Redis, in the record formats the mailcow UI reads
internal/dockerapi/    the mailcow dockerapi client
internal/notify/       direct-to-MX mail, webhook, throttle
internal/metrics/      Prometheus collectors and the HTTP endpoint
internal/whois/        registry lookups for ban notifications
```

Three shell constructs disappear:

| Shell | Here | Why |
|---|---|---|
| FIFO `/tmp/com_pipe` | `chan Event` | The event carries the check and its health, so nothing has to be looked up again from `/tmp` and Redis. |
| `kill -STOP` / `-CONT` | a cooperative `Gate` | Signalling a stopped process pauses a probe mid-handshake and can lose a `SIGCONT`. Runners pause between rounds instead. |
| `kill -USR1` | `Tracker.Heal(2)` | A method that works, unlike the trap it replaces. |

### Probe replacements

| Was | Now |
|---|---|
| `check_http`, `check_tcp`, `check_smtp`, `check_imap`, `check_clamd` | `net`, `net/http`, `crypto/tls`, `net/textproto` |
| `check_mysql`, `check_mysql_query`, `check_mysql_slavestatus.sh` | `database/sql` + `go-sql-driver/mysql` |
| `check_dns.sh` (`dig` + `perl` for timing) | `miekg/dns`, including the DNSSEC AD flag |
| `redis-cli` | `redis/go-redis` |
| `smtp-cli` (Perl, curl'd from GitHub) | `net/smtp` with MX lookup and direct delivery |
| `curl` + `jq` against dockerapi | `net/http` + `encoding/json` |
| `whois` | `internal/whois` (IANA referral, then the regional registry) |

TLS verification is disabled in exactly two places, both annotated: the dockerapi
client (self-signed certificate on an internal network) and the internal service
probes (they connect to container IPs while the certificates name the public
hostname — the Nagios plugins behaved the same way, and `certExpiry` checks the
validity dates explicitly).

---

## Configuration

Every variable from the original is honoured. Additions:

| Variable | Default | Meaning |
|---|---|---|
| `WATCHDOG_METRICS_LISTEN` | `:9393` | Metrics/health endpoint. Empty disables it. |
| `LOG_LEVEL` | `info` (`debug` under `DEV_MODE`) | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `json` (`text` under `DEV_MODE`) | `json` or `text` |
| `WATCHDOG_SETTLE_DELAY` | `30s` | Grace period before the first probe |
| `DBSOCKET` | `/var/run/mysqld/mysqld.sock` | Shared MariaDB socket |
| `MAILQ_SPOOL_DIR` | `/var/spool/postfix/deferred` | Deferred queue mount |
| `DOCKER_API_URL` | derived from `COMPOSE_PROJECT_NAME` | `https://…` or `unix:///var/run/docker.sock` |
| `DOCKER_API_DIALECT` | `auto` | `auto`, `mailcow` or `engine` |

`:9393` sits deliberately outside 9100-9999. That range is the Prometheus
project's exporter registry and is fully allocated — 9099, the obvious first
choice, belongs to the SQL exporter — and the wiki's advice for an application's
own exporter is to stay out of it. 9393 also avoids every port mailcow uses
internally (8081, 8642, 9000-9002, 9900, 10001, 10055, 11332-11334, 20000).

### Talking to Docker

The scheme of `DOCKER_API_URL` picks both the transport and the API dialect:

| URL | Transport | Dialect |
|---|---|---|
| `https://dockerapi.<project>_mailcow-network` | TLS, verification off | mailcow dockerapi |
| `unix:///var/run/docker.sock` | unix socket | Docker Engine |

`DOCKER_API_DIALECT` overrides the second column for the unusual combination of a
mailcow dockerapi reachable over a socket.

The two endpoints answer the same requests in different shapes — the daemon puts
the compose labels at the top level of its container list rather than under
`Config`, reports `State` there as a word rather than an object, and serves
`/top` as a `GET` returning `{Titles, Processes}` instead of a `POST` returning
`{msg: {Processes}}`. The client normalises both, so nothing downstream knows
which one it is talking to. Because the daemon's list omits the start time, the
uptime rule costs one extra inspection per restart decision; address lookups,
which run every round, deliberately use the cheap list only.

Be aware of the trade: mailcow runs the `dockerapi` container precisely so the
watchdog can restart containers **without** holding the full Docker API. Mounting
the daemon socket gives it everything.

Note the inherited quirks, preserved on purpose: `SKIP_SOGO`, `SKIP_CLAMD` and
`SKIP_OLEFY` are inverted (`n` means *run* the check), and `USE_WATCHDOG=n` makes
the process idle rather than exit, so compose does not see a crash loop.

mailcow's `docker-compose.yml` passes every threshold explicitly, so the defaults
in `internal/config` only apply when the watchdog runs outside the compose stack.
They mirror the compose values.

---

## Development

```sh
make build     # static binary into bin/
make test      # race detector
make cover     # coverage profile
make lint      # golangci-lint
make vuln      # govulncheck
make ci        # fmt, vet, lint, vuln, test, build
make image     # container image
```

The `go` directive pins a patch version: `1.26.6` is the first release without
the five standard-library advisories govulncheck flags.

Test coverage is 72% overall — 97% for the error-budget arithmetic, 96% for the
configuration, 89% for the supervisor. The protocol probes run against fake
servers on loopback (SMTP, LMTP, IMAP with TLS, DNS, whois, unix-socket HTTP),
so the suite needs no mailcow stack and no network.
