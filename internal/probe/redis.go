package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// RedisPinger is the subset of a Redis client the liveness probe needs.
type RedisPinger interface {
	Ping(ctx context.Context) error
}

// RedisReader is the subset used by the probes that watch mailcow's own state
// keys. Keeping it this narrow lets every one of them be tested against a map.
type RedisReader interface {
	// Get returns the value and whether the key existed.
	Get(ctx context.Context, key string) (string, bool, error)
	// HKeys returns the field names of a hash, or nil when it does not exist.
	HKeys(ctx context.Context, key string) ([]string, error)
	// LRange returns a slice of a list, inclusive on both ends.
	LRange(ctx context.Context, key string, start, stop int64) ([]string, error)
}

// RedisPing replaces the check_tcp AUTH/PING conversation the shell used to test
// the local Redis container.
type RedisPing struct {
	name   string
	client RedisPinger
}

// NewRedisPing returns a Redis liveness probe.
func NewRedisPing(name string, client RedisPinger) *RedisPing {
	return &RedisPing{name: name, client: client}
}

// Name implements Probe.
func (p *RedisPing) Name() string { return p.name }

// Run implements Probe.
func (p *RedisPing) Run(ctx context.Context) Result {
	if err := p.client.Ping(ctx); err != nil {
		return Critical("%s: Redis did not answer PING: %v", p.name, err)
	}
	return OK("%s: Redis answered PONG", p.name)
}

// RedisFlag fails while a key does not hold an expected value. Dovecot's
// replicator publishes DOVECOT_REPL_HEALTH this way, and anything other than
// "1" means replication is not keeping up.
type RedisFlag struct {
	name   string
	client RedisReader
	key    string
	want   string
}

// NewRedisFlag returns a probe that requires key to equal want.
func NewRedisFlag(name string, client RedisReader, key, want string) *RedisFlag {
	return &RedisFlag{name: name, client: client, key: key, want: want}
}

// Name implements Probe.
func (p *RedisFlag) Name() string { return p.name }

// Run implements Probe.
func (p *RedisFlag) Run(ctx context.Context) Result {
	got, _, err := p.client.Get(ctx, p.key)
	if err != nil {
		return Unknown("%s: cannot read %s: %v", p.name, p.key, err)
	}
	if got != p.want {
		return Critical("%s: %s is %q, want %q", p.name, p.key, got, p.want)
	}
	return OK("%s: %s is %q", p.name, p.key, got)
}

// RedisChange fails on the round in which a key's value changes.
//
// mailcow uses this pattern for ACME_FAIL_TIME: acme-mailcow stamps the key
// whenever a certificate request fails, so a changed value means "something went
// wrong since we last looked" rather than "the value is bad".
type RedisChange struct {
	name   string
	client RedisReader
	key    string

	mu     sync.Mutex
	seeded bool
	last   string
}

// NewRedisChange returns a change-detection probe. The first round only records
// the current value, matching the shell, which sampled the key once before
// entering its loop.
func NewRedisChange(name string, client RedisReader, key string) *RedisChange {
	return &RedisChange{name: name, client: client, key: key}
}

// Name implements Probe.
func (p *RedisChange) Name() string { return p.name }

// Run implements Probe.
func (p *RedisChange) Run(ctx context.Context) Result {
	current, _, err := p.client.Get(ctx, p.key)
	if err != nil {
		return Unknown("%s: cannot read %s: %v", p.name, p.key, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.seeded {
		p.seeded = true
		p.last = current
		return OK("%s: watching %s, now at %q", p.name, p.key, current)
	}

	previous := p.last
	p.last = current
	if previous != current {
		return Critical("%s: %s changed from %q to %q", p.name, p.key, previous, current)
	}
	return OK("%s: %s unchanged at %q", p.name, p.key, current)
}

// Ratelimit fails on the round in which mailcow applied a new rate limit.
//
// RL_LOG is a list of JSON records pushed by rspamd; the newest entry's queue id
// identifies it. A changed queue id means at least one new limit was applied
// since the previous round.
type Ratelimit struct {
	name   string
	client RedisReader

	mu     sync.Mutex
	seeded bool
	lastID string
}

// NewRatelimit returns a rate limit change probe.
func NewRatelimit(name string, client RedisReader) *Ratelimit {
	return &Ratelimit{name: name, client: client}
}

// Name implements Probe.
func (p *Ratelimit) Name() string { return p.name }

// Run implements Probe.
func (p *Ratelimit) Run(ctx context.Context) Result {
	head, err := p.client.LRange(ctx, "RL_LOG", 0, 0)
	if err != nil {
		return Unknown("%s: cannot read RL_LOG: %v", p.name, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// An empty list cannot hold a rate limit that was just applied. The shell
	// compared the two strings and alerted on any difference, so a Redis that
	// restarted without persistence, or a list deleted from the UI's debug page,
	// produced "a new rate limit was applied (queue id )" — an alert with no
	// identifier in it and, because Details reads the same empty list, no body
	// either. See DEVIATIONS.md.
	if len(head) == 0 {
		p.seeded = true
		p.lastID = ""
		return OK("%s: no rate limits recorded", p.name)
	}

	current := queueID(head[0])

	if !p.seeded {
		p.seeded = true
		p.lastID = current
		return OK("%s: watching RL_LOG", p.name)
	}

	previous := p.lastID
	p.lastID = current
	if previous == current {
		return OK("%s: no new rate limits applied", p.name)
	}
	return Critical("%s: a new rate limit was applied (queue id %s)", p.name, current)
}

// Details renders the report the notification carries: the most recent entries,
// as the shell wrote them to /tmp/ratelimit.
func (p *Ratelimit) Details(ctx context.Context) string {
	entries, err := p.client.LRange(ctx, "RL_LOG", 0, 10)
	if err != nil {
		return fmt.Sprintf("Could not read RL_LOG: %v", err)
	}

	var b strings.Builder
	b.WriteString("Last 10 applied ratelimits (may overlap with previous reports).\n")
	b.WriteString("Full ratelimit buckets can be emptied by deleting the ratelimit hash " +
		"from within the mailcow UI (see /debug -> Protocols -> Ratelimit):\n\n")
	for _, entry := range entries {
		b.WriteString(indentJSON(entry))
		b.WriteByte('\n')
	}
	return b.String()
}

// queueID extracts the .qid field the shell pulled out with jq.
//
// A record that does not parse falls back to the record itself, which is what
// makes "unchanged" mean unchanged. Returning an empty id instead — as this did,
// and as `jq .qid` did on malformed input — made the same unreadable entry read
// as a change on the round it appeared and as unchanged ever after, so the check
// alerted once, with an empty queue id, about nothing that happened. The
// fallback keeps a genuinely new unreadable entry detectable, which an id of ""
// would have swallowed.
func queueID(record string) string {
	var parsed struct {
		QID string `json:"qid"`
	}
	if err := json.Unmarshal([]byte(record), &parsed); err != nil {
		return strings.TrimSpace(record)
	}
	return parsed.QID
}

// indentJSON pretty-prints a record for the notification body, falling back to
// the raw string when it is not JSON.
func indentJSON(raw string) string {
	var pretty json.RawMessage
	if err := json.Unmarshal([]byte(raw), &pretty); err != nil {
		return raw
	}
	out, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		return raw
	}
	return string(out)
}

// Fail2ban fails on the round in which netfilter-mailcow added new bans.
//
// The bans are the field names of the F2B_ACTIVE_BANS hash. Only additions
// matter; entries disappearing are expiring bans.
//
// The shell handed the new bans to its main loop through a Redis key (F2B_RES)
// because a bash subshell cannot return data any other way. That key is
// watchdog-internal, so the Go version carries the list in the event instead and
// never writes it.
type Fail2ban struct {
	name   string
	client RedisReader

	mu     sync.Mutex
	seeded bool
	known  map[string]struct{}
	fresh  []string
}

// NewFail2ban returns a ban-detection probe.
func NewFail2ban(name string, client RedisReader) *Fail2ban {
	return &Fail2ban{name: name, client: client, known: map[string]struct{}{}}
}

// Name implements Probe.
func (p *Fail2ban) Name() string { return p.name }

// Run implements Probe.
func (p *Fail2ban) Run(ctx context.Context) Result {
	bans, err := p.client.HKeys(ctx, "F2B_ACTIVE_BANS")
	if err != nil {
		return Unknown("%s: cannot read F2B_ACTIVE_BANS: %v", p.name, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	current := make(map[string]struct{}, len(bans))
	var added []string
	for _, ban := range bans {
		current[ban] = struct{}{}
		if _, seen := p.known[ban]; !seen && p.seeded {
			added = append(added, ban)
		}
	}
	sort.Strings(added)

	p.known = current
	p.fresh = added
	if !p.seeded {
		p.seeded = true
		return OK("%s: watching %d active bans", p.name, len(bans))
	}
	if len(added) == 0 {
		return OK("%s: no new bans", p.name)
	}
	return Critical("%s: %d new ban(s): %s", p.name, len(added), strings.Join(added, " "))
}

// Fresh returns the bans added during the most recent round, so the supervisor
// can look each of them up and notify separately.
func (p *Fail2ban) Fresh() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.fresh...)
}
