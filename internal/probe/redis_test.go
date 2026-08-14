package probe

import (
	"context"
	"errors"
	"strings"
	"testing"

	"bodsch.me/mailcow-watchdog/internal/health"
)

// fakeRedis is an in-memory stand-in for the state keys mailcow's other
// containers publish. Nothing here needs a real Redis.
type fakeRedis struct {
	strings map[string]string
	hashes  map[string][]string
	lists   map[string][]string
	err     error
	pingErr error
}

func newFakeRedis() *fakeRedis {
	return &fakeRedis{
		strings: map[string]string{},
		hashes:  map[string][]string{},
		lists:   map[string][]string{},
	}
}

func (f *fakeRedis) Ping(context.Context) error { return f.pingErr }

func (f *fakeRedis) Get(_ context.Context, key string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	v, ok := f.strings[key]
	return v, ok, nil
}

func (f *fakeRedis) HKeys(_ context.Context, key string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.hashes[key], nil
}

func (f *fakeRedis) LRange(_ context.Context, key string, start, stop int64) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	list := f.lists[key]
	if int(start) >= len(list) {
		return nil, nil
	}
	end := int(stop) + 1
	if end > len(list) {
		end = len(list)
	}
	return list[start:end], nil
}

func TestRedisPing(t *testing.T) {
	fake := newFakeRedis()
	if res := runProbe(t, NewRedisPing("redis", fake)); res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}

	fake.pingErr = errors.New("connection refused")
	if res := runProbe(t, NewRedisPing("redis", fake)); res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
}

// Dovecot's replicator publishes DOVECOT_REPL_HEALTH; anything but "1" means
// replication is not keeping up.
func TestRedisFlag(t *testing.T) {
	fake := newFakeRedis()
	probe := NewRedisFlag("dovecot-repl", fake, "DOVECOT_REPL_HEALTH", "1")

	fake.strings["DOVECOT_REPL_HEALTH"] = "1"
	if res := runProbe(t, probe); res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}

	fake.strings["DOVECOT_REPL_HEALTH"] = "0"
	if res := runProbe(t, probe); res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL", res.Status, res.Message)
	}

	// A missing key reads as the empty string and must not pass.
	delete(fake.strings, "DOVECOT_REPL_HEALTH")
	if res := runProbe(t, probe); res.Status != health.StatusCritical {
		t.Errorf("status = %v (%s), want CRITICAL for a missing key", res.Status, res.Message)
	}
}

func TestRedisFlagReportsReadErrorsAsUnknown(t *testing.T) {
	fake := newFakeRedis()
	fake.err = errors.New("connection reset")

	res := runProbe(t, NewRedisFlag("dovecot-repl", fake, "DOVECOT_REPL_HEALTH", "1"))
	if res.Status != health.StatusUnknown {
		t.Errorf("status = %v (%s), want UNKNOWN", res.Status, res.Message)
	}
}

// ACME_FAIL_TIME is a timestamp: it is the change that signals a failure, not
// the value. The first round therefore only seeds.
func TestRedisChangeSeedsBeforeAlerting(t *testing.T) {
	fake := newFakeRedis()
	fake.strings["ACME_FAIL_TIME"] = "1700000000"
	probe := NewRedisChange("acme", fake, "ACME_FAIL_TIME")

	if res := runProbe(t, probe); res.Status != health.StatusOK {
		t.Errorf("seeding round: status = %v (%s), want OK", res.Status, res.Message)
	}
	if res := runProbe(t, probe); res.Status != health.StatusOK {
		t.Errorf("unchanged round: status = %v (%s), want OK", res.Status, res.Message)
	}

	fake.strings["ACME_FAIL_TIME"] = "1700000900"
	res := runProbe(t, probe)
	if res.Status != health.StatusCritical {
		t.Errorf("changed round: status = %v (%s), want CRITICAL", res.Status, res.Message)
	}

	// The new value becomes the baseline, so the next round is quiet again.
	if res := runProbe(t, probe); res.Status != health.StatusOK {
		t.Errorf("settled round: status = %v (%s), want OK", res.Status, res.Message)
	}
}

func TestRatelimitDetectsNewQueueID(t *testing.T) {
	fake := newFakeRedis()
	fake.lists["RL_LOG"] = []string{`{"qid":"AAA111","rcpt":"a@example.org"}`}
	probe := NewRatelimit("ratelimit", fake)

	if res := runProbe(t, probe); res.Status != health.StatusOK {
		t.Errorf("seeding round: status = %v (%s), want OK", res.Status, res.Message)
	}
	if res := runProbe(t, probe); res.Status != health.StatusOK {
		t.Errorf("unchanged round: status = %v (%s), want OK", res.Status, res.Message)
	}

	fake.lists["RL_LOG"] = []string{`{"qid":"BBB222","rcpt":"b@example.org"}`}
	res := runProbe(t, probe)
	if res.Status != health.StatusCritical {
		t.Errorf("new limit: status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "BBB222") {
		t.Errorf("message = %q, want it to name the queue id", res.Message)
	}
}

func TestRatelimitEmptyLogIsQuiet(t *testing.T) {
	fake := newFakeRedis()
	probe := NewRatelimit("ratelimit", fake)

	runProbe(t, probe)
	if res := runProbe(t, probe); res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK for an empty RL_LOG", res.Status, res.Message)
	}
}

func TestRatelimitDetails(t *testing.T) {
	fake := newFakeRedis()
	fake.lists["RL_LOG"] = []string{`{"qid":"AAA111","rcpt":"a@example.org"}`}

	details := NewRatelimit("ratelimit", fake).Details(context.Background())
	if !strings.Contains(details, "AAA111") {
		t.Errorf("details = %q, want the entry to be included", details)
	}
	if !strings.Contains(details, "Last 10 applied ratelimits") {
		t.Errorf("details = %q, want the original heading", details)
	}
}

// Only additions matter: a ban disappearing is an expiry, not an event.
func TestFail2banReportsOnlyNewBans(t *testing.T) {
	fake := newFakeRedis()
	fake.hashes["F2B_ACTIVE_BANS"] = []string{"198.51.100.7"}
	probe := NewFail2ban("fail2ban", fake)

	if res := runProbe(t, probe); res.Status != health.StatusOK {
		t.Errorf("seeding round: status = %v (%s), want OK", res.Status, res.Message)
	}

	fake.hashes["F2B_ACTIVE_BANS"] = []string{"198.51.100.7", "203.0.113.9", "203.0.113.4"}
	res := runProbe(t, probe)
	if res.Status != health.StatusCritical {
		t.Errorf("new bans: status = %v (%s), want CRITICAL", res.Status, res.Message)
	}

	fresh := probe.Fresh()
	// Fresh is sorted so notifications arrive in a stable order.
	want := []string{"203.0.113.4", "203.0.113.9"}
	if len(fresh) != len(want) {
		t.Fatalf("Fresh() = %v, want %v", fresh, want)
	}
	for i := range want {
		if fresh[i] != want[i] {
			t.Errorf("Fresh()[%d] = %q, want %q", i, fresh[i], want[i])
		}
	}

	// An expiring ban is not an event.
	fake.hashes["F2B_ACTIVE_BANS"] = []string{"203.0.113.9"}
	if res := runProbe(t, probe); res.Status != health.StatusOK {
		t.Errorf("expiry round: status = %v (%s), want OK", res.Status, res.Message)
	}
	if got := probe.Fresh(); len(got) != 0 {
		t.Errorf("Fresh() = %v, want it to be empty", got)
	}
}

func TestFail2banReadErrorIsUnknown(t *testing.T) {
	fake := newFakeRedis()
	fake.err = errors.New("connection reset")

	res := runProbe(t, NewFail2ban("fail2ban", fake))
	if res.Status != health.StatusUnknown {
		t.Errorf("status = %v (%s), want UNKNOWN", res.Status, res.Message)
	}
}

func TestQueueIDIgnoresUnparsableRecords(t *testing.T) {
	if got := queueID("not json"); got != "" {
		t.Errorf("queueID = %q, want an empty id", got)
	}
	if got := queueID(`{"qid":"X1"}`); got != "X1" {
		t.Errorf("queueID = %q, want X1", got)
	}
}
