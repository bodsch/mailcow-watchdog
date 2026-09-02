# mailcow-watchdog

A Go rewrite of the `watchdog.sh` that ships with
[mailcow-dockerized](https://github.com/mailcow/mailcow-dockerized).

It is a **drop-in replacement**: the same environment variables configure it, the
same Redis keys carry its state, and container restarts still go through the
mailcow `dockerapi` service. Swapping the image is enough — `mailcow.conf` needs
no changes. Where the behaviour differs anyway, it is listed in
[DEVIATIONS.md](DEVIATIONS.md).

The original is preserved under `original/watchdog/` for reference. The house
style this repository shares with
[mailcow-dockerapi](https://github.com/mailcow/mailcow-dockerized) is written down
in [CONVENTIONS.md](CONVENTIONS.md).

---

## Why

The shell version worked, but its structure made three things hard:

- **Efficiency.** Every round forked a Nagios plugin, `dig`, `redis-cli`,
  `mariadb`, `curl` and `jq`. Nineteen check loops did this continuously. All of
  that is now in-process.
- **Code quality.** The nineteen check functions were the same twelve lines of
  error accounting copy-pasted, which is how several of them drifted apart.
- **Testability.** Nothing was testable. The bugs listed in
  [DEVIATIONS.md](DEVIATIONS.md) had been in production for years because there
  was no way to notice them.

The runtime image went from Alpine plus ~25 packages — including an `smtp-cli`
downloaded from GitHub at build time over an unpinned URL — to a single static
binary on distroless.

---

## What's new

- **Prometheus metrics** on `:9393/metrics` (`WATCHDOG_METRICS_LISTEN`):
  per-check health and error budget, probe latency histograms and outcome
  counters, restart counters by result, notification outcomes, and a `paused`
  gauge. `mailcow_watchdog_build_info{version,build_date}` identifies the running
  binary — see [Version stamping](#version-stamping).
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
internal/metrics/      Prometheus collectors
internal/obs/          the /metrics, /healthz and /readyz endpoint
internal/logging/      the structured logger
internal/whois/        registry lookups for ban notifications
original/              the replaced implementation, for reference
```

The shell constructs that disappear, and the tooling that goes with them, are
listed in [DEVIATIONS.md](DEVIATIONS.md).

---

## Configuration

Every variable from the original is honoured. Additions:

| Variable | Default | Meaning |
|---|---|---|
| `WATCHDOG_METRICS_LISTEN` | `:9393` | Metrics/health endpoint. Empty disables it. |
| `LOG_LEVEL` | `info` (`debug` under `DEV_MODE`) | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `json` (`text` under `DEV_MODE`) | `json` or `text` |
| `WATCHDOG_SETTLE_DELAY` | `30s` | Grace period before the first probe |
| `WATCHDOG_CHECK_INTERVAL` | `20s` | Shortest pause between two rounds of the same check |
| `DBSOCKET` | `/var/run/mysqld/mysqld.sock` | Shared MariaDB socket |
| `MAILQ_SPOOL_DIR` | `/var/spool/postfix/deferred` | Deferred queue mount |
| `DOCKER_API_URL` | derived from `COMPOSE_PROJECT_NAME` | `https://…` or `unix:///var/run/docker.sock` |
| `DOCKER_API_DIALECT` | `auto` | `auto`, `mailcow` or `engine` |

`WATCHDOG_CHECK_INTERVAL` is how the watchdog is asked to be calmer than the
original, whose sleeps were hard-coded in the script. It sets the lower bound of
every check's sleep window; the jitter above it stays the size watchdog.sh used
(up to 59s, up to 119s for clamd), because its job is to keep nineteen checks
from hitting the stack in lockstep, not to widen with the interval.

At the default the cadence is exactly the shell's: rounds every 20–79 seconds.
At `5m` they are 5m–5m59s. The certificate check (a flat 5m) and the external
checks (30m) keep their own longer sleeps until the configured bound overtakes
them, and then follow it.

Raising it raises the time to notice an outage by the same amount: a container is
restarted once `Threshold` error points have accumulated, and those are earned
one round at a time. `0` and negative values are refused at startup — either
would make every sleep return at once and turn the checks into a load generator
against the stack they measure.

`WATCHDOG_METRICS_LISTEN` is an address to **bind**, not a URL to scrape: `":9393"`, or
`"127.0.0.1:9393"` to keep it off the network. A URL such as
`http://127.0.0.1:9393/metrics` is rejected at startup — the paths of the three
endpoints are fixed and a scheme has nowhere to go.

Inside a container, `127.0.0.1` is the container's own loopback. A published port
(`-p 9393:9393`) forwards to the container's bridge address instead, finds
nothing listening there, and a scrape fails with a **reset connection** rather than
a refused one — which reads like a server problem and is not one. Bind `":9393"`
when the endpoint has to be reachable from outside the container.

`:9393` sits deliberately outside 9100-9999. That range is the Prometheus
project's exporter registry and is fully allocated — 9099, the obvious first
choice, belongs to the SQL exporter — and the wiki's advice for an application's
own exporter is to stay out of it. 9393 also avoids every port mailcow uses
internally (8081, 8642, 9000-9002, 9900, 10001, 10055, 11332-11334, 20000). The
dockerapi serves the same three endpoints one port up, on 9394.

### Talking to Docker

The scheme of `DOCKER_API_URL` picks both the transport and the API dialect:

| URL | Transport | Dialect |
|---|---|---|
| `https://dockerapi.<project>_mailcow-network` | TLS, verification off | mailcow dockerapi |
| `unix:///var/run/docker.sock` | unix socket | Docker Engine |

`DOCKER_API_DIALECT` overrides the second column for the unusual combination of a
mailcow dockerapi reachable over a socket.

While the endpoint is unreachable the supervisor pauses every check, so it is
probed every three seconds — over HTTPS with a full TLS handshake rather than the
`nc -z` connect-and-close the shell used. That answers the question that matters
(can a request be made at all, not just is something listening) and leaves nothing
in the dockerapi's log: a connection dropped before the ClientHello is a failed
handshake on the other side, three seconds apart, for as long as the watchdog runs.
See 2.2 in [DEVIATIONS.md](DEVIATIONS.md).

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

## Version stamping

`version` and `build_date` are linked into the binary with `-X`; they appear in the
startup line and as the labels of `mailcow_watchdog_build_info`. Every build path
stamps them:

| Build | Version | Date |
|---|---|---|
| `make build` / `make release` | `git describe --tags --always --dirty` | UTC day |
| `make image` | same, via `--build-arg` | same |
| Release workflow (tag) | the tag | UTC day |
| Container workflow (tag) | the tag | UTC day |
| plain `go build` | `dev` | `unknown` |

An image reporting `version="dev"` was therefore built without its build
arguments — `docker build` without `--build-arg VERSION=…`, or a CI step that
forgets to pass them. The date is a UTC day rather than a timestamp so two builds
of the same release stay comparable.

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
the five standard-library advisories govulncheck flags. mailcow-dockerapi pins the
same one.

Test coverage is 72% overall — 97% for the error-budget arithmetic, 96% for the
configuration, 89% for the supervisor. The protocol probes run against fake
servers on loopback (SMTP, LMTP, IMAP with TLS, DNS, whois, unix-socket HTTP),
so the suite needs no mailcow stack and no network.
