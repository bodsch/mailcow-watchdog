// Package store is the watchdog's view of Redis.
//
// Redis is not just a cache here: it is the interface between the watchdog and
// the rest of mailcow. The UI renders WATCHDOG_LOG, netfilter-mailcow publishes
// its bans through F2B_ACTIVE_BANS, acme-mailcow stamps ACME_FAIL_TIME and
// rspamd appends to RL_LOG. The record formats below are therefore fixed by the
// consumers, not by this package.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"bodsch.me/mailcow-watchdog/internal/health"
	"github.com/redis/go-redis/v9"
)

// LogKey is the list the mailcow UI reads the watchdog's history from.
const LogKey = "WATCHDOG_LOG"

// throttlePrefix namespaces the notification rate limit keys.
const throttlePrefix = "THROTTLE_"

// Store is the set of Redis operations the watchdog needs. Everything that
// talks to Redis takes this interface so it can be faked in tests.
type Store interface {
	// Ping reports whether the instance answers.
	Ping(ctx context.Context) error

	// Get returns a value and whether the key existed.
	Get(ctx context.Context, key string) (string, bool, error)
	// Set writes a value without an expiry.
	Set(ctx context.Context, key, value string) error
	// HKeys returns a hash's field names.
	HKeys(ctx context.Context, key string) ([]string, error)
	// LRange returns an inclusive slice of a list.
	LRange(ctx context.Context, key string, start, stop int64) ([]string, error)

	// LogMessage appends a free-text entry to WATCHDOG_LOG.
	LogMessage(ctx context.Context, message string) error
	// LogProgress appends a health entry to WATCHDOG_LOG.
	LogProgress(ctx context.Context, snapshot health.Snapshot) error

	// Reserve claims a throttle slot for key. It reports whether the caller may
	// proceed and, when it may not, how long the current reservation still has
	// to run.
	Reserve(ctx context.Context, key string, ttl time.Duration) (bool, time.Duration, error)

	// Close releases the connection pool.
	Close() error
}

// progressEntry is the health record the mailcow UI parses. Every value is a
// string, including the numbers — that is how watchdog.sh emitted it and the UI
// has been reading it ever since.
type progressEntry struct {
	Time    string `json:"time"`
	Service string `json:"service"`
	Level   string `json:"lvl"`
	Now     string `json:"hpnow"`
	Total   string `json:"hptotal"`
	Diff    string `json:"hpdiff"`
}

// messageEntry is the free-text record.
type messageEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
}

// Redis is the production Store.
type Redis struct {
	client *redis.Client
	now    func() time.Time
}

// Options configures the client.
type Options struct {
	// Addr is the instance to talk to. When mailcow runs Redis in replication
	// this is the primary, because the local replica rejects writes.
	Addr     string
	Password string
	// Now is injectable so tests can pin the timestamps in the log records.
	Now func() time.Time
}

// New returns a Store backed by a real Redis connection.
func New(opts Options) *Redis {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Redis{
		client: redis.NewClient(&redis.Options{
			Addr:     opts.Addr,
			Password: opts.Password,
		}),
		now: now,
	}
}

// Ping implements Store.
func (r *Redis) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Get implements Store. A missing key is reported through the boolean rather
// than as an error, because "not set yet" is a normal state for most of the keys
// the watchdog reads.
func (r *Redis) Get(ctx context.Context, key string) (string, bool, error) {
	value, err := r.client.Get(ctx, key).Result()
	switch {
	case err == redis.Nil:
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("GET %s: %w", key, err)
	default:
		return value, true, nil
	}
}

// Set implements Store.
func (r *Redis) Set(ctx context.Context, key, value string) error {
	if err := r.client.Set(ctx, key, value, 0).Err(); err != nil {
		return fmt.Errorf("SET %s: %w", key, err)
	}
	return nil
}

// HKeys implements Store.
func (r *Redis) HKeys(ctx context.Context, key string) ([]string, error) {
	fields, err := r.client.HKeys(ctx, key).Result()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("HKEYS %s: %w", key, err)
	}
	return fields, nil
}

// LRange implements Store.
func (r *Redis) LRange(ctx context.Context, key string, start, stop int64) ([]string, error) {
	values, err := r.client.LRange(ctx, key, start, stop).Result()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("LRANGE %s: %w", key, err)
	}
	return values, nil
}

// LogMessage implements Store.
func (r *Redis) LogMessage(ctx context.Context, message string) error {
	encoded, err := EncodeMessage(message, r.now())
	if err != nil {
		return err
	}
	return r.push(ctx, encoded)
}

// LogProgress implements Store.
func (r *Redis) LogProgress(ctx context.Context, s health.Snapshot) error {
	encoded, err := EncodeProgress(s, r.now())
	if err != nil {
		return err
	}
	return r.push(ctx, encoded)
}

// EncodeMessage renders a free-text log record exactly as the mailcow UI expects
// to read it back.
func EncodeMessage(message string, at time.Time) ([]byte, error) {
	return encode(messageEntry{
		Time:    timestamp(at),
		Message: Sanitize(message),
	})
}

// EncodeProgress renders a health log record. Every field is a string, numbers
// included, because that is the shape watchdog.sh produced.
func EncodeProgress(s health.Snapshot, at time.Time) ([]byte, error) {
	return encode(progressEntry{
		Time:    timestamp(at),
		Service: s.Service,
		Level:   strconv.Itoa(s.Percent),
		Now:     strconv.Itoa(s.Remaining),
		Total:   strconv.Itoa(s.Threshold),
		Diff:    strconv.Itoa(s.Trend),
	})
}

func encode(entry any) ([]byte, error) {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("encoding a %s entry: %w", LogKey, err)
	}
	return encoded, nil
}

func timestamp(at time.Time) string {
	return strconv.FormatInt(at.Unix(), 10)
}

// Reserve implements Store.
//
// watchdog.sh read the key's TTL and then wrote it, which both raced against a
// second notification and got stuck whenever the key happened to carry no expiry
// (TTL -1 fell into the "blocked" branch forever). SET NX EX does the whole
// thing atomically and cannot end up in that state.
func (r *Redis) Reserve(ctx context.Context, key string, ttl time.Duration) (bool, time.Duration, error) {
	full := throttlePrefix + key

	ok, err := r.client.SetNX(ctx, full, "1", ttl).Result()
	if err != nil {
		return false, 0, fmt.Errorf("SET NX %s: %w", full, err)
	}
	if ok {
		return true, 0, nil
	}

	left, err := r.client.TTL(ctx, full).Result()
	if err != nil {
		// The slot is taken; not knowing for how long does not change that.
		return false, 0, nil
	}
	if left < 0 {
		left = 0
	}
	return false, left, nil
}

// Close implements Store.
func (r *Redis) Close() error { return r.client.Close() }

// push prepends a record to the log the UI reads.
func (r *Redis) push(ctx context.Context, encoded []byte) error {
	if err := r.client.LPush(ctx, LogKey, encoded).Err(); err != nil {
		return fmt.Errorf("LPUSH %s: %w", LogKey, err)
	}
	return nil
}

// sanitized is the set of characters watchdog.sh replaced with a space before
// storing a message:
//
//	tr '\r\n%&;$"_[]{}-' ' '
//
// The UI has always received messages with these stripped, so the replacement is
// kept even though a JSON encoder would handle the quoting correctly on its own.
const sanitized = "\r\n%&;$\"_[]{}-"

// Sanitize applies that replacement.
func Sanitize(message string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(sanitized, r) {
			return ' '
		}
		return r
	}, message)
}
