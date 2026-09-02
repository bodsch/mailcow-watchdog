# Deviations from watchdog.sh

The Go implementation is meant as a replacement that needs no change to an
existing mailcow deployment: the same environment variables configure it, the same
Redis keys carry its state, and container restarts still go through the mailcow
`dockerapi` service. This document records where the behaviour differs anyway —
and why.

References point at `original/watchdog/`.

## 1. Fixed bugs

These were found while porting. All of them are fixed here; the behaviour is
otherwise unchanged.

### 1.1 The self-healing never worked (all 19 checks)

```sh
trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
```

The double quotes mean `${err_count}` expanded to `0` when the trap was
*installed*. The trap body was literally `[ 0 -gt 1 ] && err_count=-2` — a no-op.
The documented "reduce the error count by 2 after restarting an unhealthy
container" feature did not exist.

**Now:** `Tracker.Heal(2)`, a method that works.

### 1.2 The IPv6 report was lost (`external_checks`)

The IPv6 failure branch stored `${CHECK_REPONSE}` — the IPv4 body — instead of
`${CHECK_REPONSE6}`.

**Now:** Each address family reports its own transcript.

### 1.3 A permanent false alarm in the certificate check (`cert_checks`)

The check resolved `postfix` and `dovecot` instead of `postfix-mailcow` /
`dovecot-mailcow`. Under `IP_BY_DOCKER_API=1` the exact label match found nothing,
returned the placeholder `240.0.0.0`, and the check reported an expiry problem
forever.

**Now:** The compose service names.

### 1.4 Redis replication was ignored (`dovecot_repl`, `ratelimit`, `acme`)

These hard-coded `redis-cli -h redis` and ignored `REDIS_SLAVEOF_IP`, so only some
calls honoured the replication setup.

**Now:** Every write goes to the configured primary. The redis check itself
deliberately probes the container-local instance, because its event restarts that
container.

### 1.5 One worker pass took minutes instead of seconds (worker monitor)

`sleep 10` sat *inside* the `for` loop over all workers, so one full pass took
about three minutes rather than ten seconds.

**Now:** Runners are independent goroutines.

### 1.6 A notification could be throttled forever (`notify_error`)

The throttle only re-armed when `TTL` returned `-2`. A key with no expiry (`-1`)
blocked that notification permanently. It was also a read-then-write race.

**Now:** A single atomic `SET NX EX`.

### 1.7 Webhook bodies could be invalid JSON

Placeholders were substituted with `sed`, escaping only `/` and `&`. A subject or
transcript containing `"`, `\` or a newline produced invalid JSON that the webhook
silently rejected.

**Now:** Values are JSON-escaped.

### 1.8 `usr/bin/curl` without a leading slash (`rspamd_checks`)

It only worked because the working directory happened to be `/`.

**Now:** No curl at all — `net/http` over the unix socket.

### 1.9 A resolved address was never used (`redis_checks`)

The check resolved a container IP into `host_ip` and then ignored it.

**Now:** The probe talks to the instance it measures.

### 1.10 A threshold of `0` restarted a container in a tight loop

A check with threshold zero declared its service dead before the first probe.

**Now:** Rejected at startup.

### 1.11 A cleared `RL_LOG` raised an alert nobody could act on

`ratelimit_checks` compared `jq .qid` of the newest `RL_LOG` entry against the
previous round's and alerted on any difference. An empty list yields an empty
string, so a Redis that restarted without persistence — or a list deleted from the
UI's debug page — differed from whatever preceded it and produced:

```
Ratelimit: a new rate limit was applied (queue id )
```

No identifier in it, and no body either: the details are read from the same empty
list. The port inherited this, comment included — `queueID` claimed an unparsable
record "simply reads as unchanged", which was the opposite of what it did. An
unreadable entry produced the same empty id, so it alerted once about nothing and
then never again about the same entry.

**Now:** an empty list is reported as "no rate limits recorded", and an entry that
does not parse is identified by the record itself rather than by an empty string.
The same unreadable entry twice is unchanged, which is what the comment promised;
a *different* unreadable entry is still a change, so nothing that really happened
is swallowed. Covered by `TestRatelimitSurvivesAClearedLog`,
`TestRatelimitDoesNotAlertOnAnUnreadableEntryTwice` and
`TestQueueIDIdentifiesARecordItCannotParse`.

---

## 2. Intentional behaviour changes

### 2.1 `F2B_RES` is no longer written

It was a private channel between the fail2ban check's subshell and the main loop —
the only way a bash subshell could return data. New bans now travel in the event
itself.

### 2.2 The dockerapi probe completes the TLS handshake

`watchdog.sh:1081` monitored the API with `while nc -z dockerapi 443; do sleep 3`,
and this implementation took that over as a connect-and-close every
`DockerAPIPoll`. Seen from the other end, a connection that closes before the
ClientHello is a failed TLS handshake, so the dockerapi logged one every three
seconds for as long as the watchdog ran — with nothing but an address in the line,
which is a container the address belongs to only until the next restart.

**Now:** over HTTPS the probe carries the handshake through
(`internal/dockerapi.dialTCP`), with the transport's TLS config, so the same
verification applies as to a request. Nothing is logged on the server side, and the
answer is the more useful one: a listener that accepts but cannot serve TLS is
reported as unreachable rather than as an endpoint the supervisor resumes every
check for. Over plain HTTP there is no handshake and the probe stays a connection.

### 2.3 A certificate verdict names the certificate

`check_smtp -D 7` and `check_imap -D 7` reported only the dates, so the message
was "certificate expired on <date>" and nothing more.

That reads as a broken probe. The case it comes from is a stack still serving the
example pair mailcow ships, whose `notAfter` is `Nov 28 10:11:00 2019 GMT`: the
verdict is correct, the mail server really is presenting a certificate that
expired in 2019, but a log line naming a date seven years in the past next to a
successful ACME renewal points the operator at the watchdog rather than at the
deployment.

**Now:** every certificate verdict carries the subject and the issuer
(`internal/probe.describe`), and a certificate that names itself as its own
issuer is called self-signed instead. For the case above the line reads:

```
dovecot-cert: dovecot-mailcow:993: certificate expired on 2019-11-28T10:11:00Z,
subject "CN=mail.example.org,O=mailcow", issuer "O=mailcow"
```

which answers from the log alone which certificate the probe looked at. The test
uses that certificate itself as its fixture rather than one shaped like it: a
generated stand-in came out strictly self-signed, while mailcow's is signed by a
separate `O=mailcow` issuer, and testing against the friendlier shape would have
pinned a message the field never produces.

### 2.4 A TCP probe no longer claims a reply it never read

php-fpm (9001, 9002), postfix-tlspol (8642) and olefy (10055) are probed with
`check_tcp` and no expected string, exactly as watchdog.sh did — olefy is even
sent a `PING\n` whose answer nobody reads. The check is therefore "the port
accepts a connection", and a wedged worker that accepts and then falls silent
passes it. That behaviour is inherited deliberately.

The verdict was not. All four reported `responded as expected`, which claims a
reply the probe never asked for; Nagios reported a connection time instead and
claimed nothing. An operator chasing an outage reads "responded as expected" as
proof the service answered and looks elsewhere.

**Now:** without an expected string the verdict is `accepted a connection, nothing
was read back`, and with one it names what it found. The two cases are
distinguishable in the log, which is the point.

## 3. Deliberately preserved quirks

These look accidental but stay as they are, because the deployment builds on them.

- **Nagios exit codes are summed into the error budget**, so a `CRITICAL` costs two
  points and a `WARNING` one. The thresholds in `mailcow.conf` are calibrated
  against it. Preserved exactly — see `internal/health`.
- **Checks the shell implemented itself always added exactly one point**,
  regardless of severity. Preserved via the `probe.Cost(1, …)` wrapper, which keeps
  the reported severity honest for logs and metrics while pinning the cost.
- **The health percentage** uses the original's integer arithmetic
  (`((200*c/t)%2) + (100*c/t)`), verified against `bash` output, so the bars in the
  mailcow UI do not shift.
- **`WATCHDOG_LOG` record shapes** are byte-identical, including the message
  sanitiser (`tr '\r\n%&;$"_[]{}-' ' '`) that turns `nginx-mailcow` into
  `nginx mailcow`.
- **The replication query stays `SHOW SLAVE STATUS`.** MariaDB added `REPLICA` as a
  statement synonym in 10.5.1 ([MDEV-20601](https://jira.mariadb.org/browse/MDEV-20601))
  but deliberately left the result columns alone, so `SHOW REPLICA STATUS` still
  returns `Slave_IO_Running`, not `Replica_IO_Running`. Switching the statement
  would buy nothing and would break the check on older installations. The Go code's
  own vocabulary is primary/replica throughout; only the four column constants keep
  MariaDB's spelling, because that is what the server sends.
- **`SKIP_SOGO`, `SKIP_CLAMD` and `SKIP_OLEFY` are inverted** — `n` means *run* the
  check.
- **`USE_WATCHDOG=n` makes the process idle rather than exit**, so compose does not
  see a crash loop.

## 4. Additions

### 4.1 `WATCHDOG_CHECK_INTERVAL`

The sleep windows were hard-coded: `sleep $(( ( RANDOM % 60 ) + 20 ))` for
seventeen checks, `RANDOM % 120 + 20` for clamd, `sleep 300` for the certificate
check and half an hour for the external ones. Nineteen checks therefore probed a
mailcow every twenty to seventy-nine seconds whether or not that was wanted, and
the only way to calm it down was to edit the script inside the image.

`WATCHDOG_CHECK_INTERVAL` (a duration, default `20s` — the shell's own lower
bound) is the shortest pause between two rounds of the same check.
`check.Intervals` derives the four windows from it:

| Window | Default | At `WATCHDOG_CHECK_INTERVAL=5m` |
|---|---|---|
| standard (17 checks) | 20–79s | 5m–5m59s |
| clamd | 20–139s | 5m–6m59s |
| external | 30m–30m19s | 30m–30m19s |
| cert | 5m | 5m |

Two decisions are worth recording. The jitter keeps the size the shell gave it
instead of scaling with the interval: its job is to stop nineteen checks from
hitting the stack in lockstep, and a minute of spread does that as well at
five-minute rounds as at twenty-second ones. Scaling it would make
`WATCHDOG_CHECK_INTERVAL=5m` mean "somewhere between five and twenty minutes",
which is a different request. And the two long checks are raised to the
configured bound but never lowered below their own, so asking for hourly rounds
does not leave the certificate probe running every five minutes, while asking for
faster rounds does not send the external checks out over the public network every
twenty seconds.

Zero and negative values are refused at startup. Either would make every sleep
return immediately, and nineteen checks in a tight loop would hammer the very
stack they measure — a watchdog that reads as configured and behaves like a load
generator.

Raising it raises the time to notice an outage by the same amount. A container
that stops answering is restarted after `Threshold` points have accumulated, and
those points are earned one round at a time.

## 5. Technical differences with no effect on the interface

Three shell constructs disappear:

| Shell | Here | Why |
|---|---|---|
| FIFO `/tmp/com_pipe` | `chan Event` | The event carries the check and its health, so nothing has to be looked up again from `/tmp` and Redis. |
| `kill -STOP` / `-CONT` | a cooperative `Gate` | Signalling a stopped process pauses a probe mid-handshake and can lose a `SIGCONT`. Runners pause between rounds instead. |
| `kill -USR1` | `Tracker.Heal(2)` | A method that works, unlike the trap it replaces. |

The external tooling is gone with it:

| Was | Now |
|---|---|
| `check_http`, `check_tcp`, `check_smtp`, `check_imap`, `check_clamd` | `net`, `net/http`, `crypto/tls`, `net/textproto` |
| `check_mysql`, `check_mysql_query`, `check_mysql_slavestatus.sh` | `database/sql` + `go-sql-driver/mysql` |
| `check_dns.sh` (`dig` + `perl` for timing) | `miekg/dns`, including the DNSSEC AD flag |
| `redis-cli` | `redis/go-redis` |
| `smtp-cli` (Perl, curl'd from GitHub at build time) | `net/smtp` with MX lookup and direct delivery |
| `curl` + `jq` against dockerapi | `net/http` + `encoding/json` |
| `whois` | `internal/whois` (IANA referral, then the regional registry) |

TLS verification is disabled in exactly two places, both annotated: the dockerapi
client (self-signed certificate on an internal network) and the internal service
probes (they connect to container IPs while the certificates name the public
hostname — the Nagios plugins behaved the same way, and `certExpiry` checks the
validity dates explicitly).
