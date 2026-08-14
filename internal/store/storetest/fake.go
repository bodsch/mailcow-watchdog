// Package storetest provides an in-memory Store for tests.
//
// It lives in its own package so the production binary never links it, while
// every package that depends on store can still be tested without a Redis.
package storetest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"bodsch.me/mailcow-watchdog/internal/health"
	"bodsch.me/mailcow-watchdog/internal/store"
)

// Fake is a Store backed by maps. It records everything written so that tests
// can assert on the log the mailcow UI would see.
type Fake struct {
	mu sync.Mutex

	strings map[string]string
	hashes  map[string][]string
	lists   map[string][]string

	// reservations tracks throttle slots and when they expire.
	reservations map[string]time.Time

	// Log holds the encoded WATCHDOG_LOG entries, newest first, mirroring LPUSH.
	Log []string

	// Now drives both the log timestamps and throttle expiry. It defaults to a
	// fixed instant so encoded records are reproducible.
	Now func() time.Time

	// Err, when set, is returned by every read operation.
	Err error
	// PingErr, when set, is returned by Ping.
	PingErr error
}

// Fixed is the default clock: 2026-01-01T00:00:00Z.
var Fixed = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// New returns an empty Fake.
func New() *Fake {
	return &Fake{
		strings:      map[string]string{},
		hashes:       map[string][]string{},
		lists:        map[string][]string{},
		reservations: map[string]time.Time{},
		Now:          func() time.Time { return Fixed },
	}
}

var _ store.Store = (*Fake)(nil)

// Ping implements store.Store.
func (f *Fake) Ping(context.Context) error { return f.PingErr }

// Get implements store.Store.
func (f *Fake) Get(_ context.Context, key string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.Err != nil {
		return "", false, f.Err
	}
	v, ok := f.strings[key]
	return v, ok, nil
}

// Set implements store.Store.
func (f *Fake) Set(_ context.Context, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.strings[key] = value
	return nil
}

// HKeys implements store.Store.
func (f *Fake) HKeys(_ context.Context, key string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.Err != nil {
		return nil, f.Err
	}
	return append([]string(nil), f.hashes[key]...), nil
}

// LRange implements store.Store.
func (f *Fake) LRange(_ context.Context, key string, start, stop int64) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.Err != nil {
		return nil, f.Err
	}
	list := f.lists[key]
	if start < 0 || int(start) >= len(list) {
		return nil, nil
	}
	end := int(stop) + 1
	if end > len(list) {
		end = len(list)
	}
	return append([]string(nil), list[start:end]...), nil
}

// LogMessage implements store.Store.
func (f *Fake) LogMessage(_ context.Context, message string) error {
	encoded, err := store.EncodeMessage(message, f.Now())
	if err != nil {
		return err
	}
	f.push(string(encoded))
	return nil
}

// LogProgress implements store.Store.
func (f *Fake) LogProgress(_ context.Context, s health.Snapshot) error {
	encoded, err := store.EncodeProgress(s, f.Now())
	if err != nil {
		return err
	}
	f.push(string(encoded))
	return nil
}

// Reserve implements store.Store with the same set-if-absent semantics as the
// real client.
func (f *Fake) Reserve(_ context.Context, key string, ttl time.Duration) (bool, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.Now()
	if until, taken := f.reservations[key]; taken && now.Before(until) {
		return false, until.Sub(now), nil
	}
	f.reservations[key] = now.Add(ttl)
	return true, 0, nil
}

// Close implements store.Store.
func (f *Fake) Close() error { return nil }

// SetString seeds a string key.
func (f *Fake) SetString(key, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.strings[key] = value
}

// SetHash seeds a hash's field names.
func (f *Fake) SetHash(key string, fields ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hashes[key] = fields
}

// SetList seeds a list.
func (f *Fake) SetList(key string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists[key] = values
}

// Entries returns the recorded WATCHDOG_LOG entries, newest first.
func (f *Fake) Entries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Log...)
}

// FindEntry returns the first recorded entry containing want, or an error naming
// what was recorded instead.
func (f *Fake) FindEntry(want string) (string, error) {
	for _, entry := range f.Entries() {
		if strings.Contains(entry, want) {
			return entry, nil
		}
	}
	return "", errors.New("no log entry contains " + want)
}

func (f *Fake) push(entry string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// LPUSH prepends, so the newest entry is first.
	f.Log = append([]string{entry}, f.Log...)
}
