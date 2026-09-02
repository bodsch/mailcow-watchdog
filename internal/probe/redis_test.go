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

// The old expectation here was that an unparsable record yields an empty id. That
// was the implementation, not the promise: the promise in the doc comment was
// that such a record "reads as unchanged", and an empty id does the opposite — it
// differs from whatever preceded it and fires an alert. The test asserted the
// bug.
func TestQueueIDIdentifiesARecordItCannotParse(t *testing.T) {
	if got := queueID(`{"qid":"X1"}`); got != "X1" {
		t.Errorf("queueID = %q, want X1", got)
	}
	// The record itself, so that the same unreadable entry twice is the same id.
	if got := queueID("not json"); got != "not json" {
		t.Errorf("queueID = %q, want the record itself so it compares as unchanged", got)
	}
	if queueID("not json") != queueID("not json ") {
		t.Error("the same unreadable record produced two different ids")
	}
	// A different unreadable record is still a change: swallowing it would lose
	// a rate limit that really was applied.
	if queueID("not json") == queueID("also not json") {
		t.Error("two different unreadable records produced the same id")
	}
}

// TestRatelimitSurvivesAClearedLog is the alert nobody could act on. RL_LOG is
// gone after a Redis that restarted without persistence, or after the list is
// deleted from the UI's debug page. The check then compared the last queue id
// against nothing, called it a change, and sent "a new rate limit was applied
// (queue id )" — no identifier in the subject and, because Details reads the same
// empty list, no body either.
//
// An operator who gets two of those learns to ignore the third, which is the one
// that matters.
func TestRatelimitSurvivesAClearedLog(t *testing.T) {
	fake := newFakeRedis()
	fake.lists["RL_LOG"] = []string{`{"qid":"AAA111","rcpt":"a@example.org"}`}
	p := NewRatelimit("ratelimit", fake)

	runProbe(t, p) // the seeding round

	fake.lists["RL_LOG"] = nil
	if res := runProbe(t, p); res.Status != health.StatusOK {
		t.Errorf("cleared log: status = %v (%s), want OK", res.Status, res.Message)
	}

	// And a real rate limit arriving afterwards is still caught, or the fix
	// would have traded a false alarm for a missed one.
	fake.lists["RL_LOG"] = []string{`{"qid":"BBB222"}`}
	res := runProbe(t, p)
	if res.Status != health.StatusCritical {
		t.Fatalf("after the clear: status = %v (%s), want CRITICAL", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "BBB222") {
		t.Errorf("message = %q, want it to name the queue id", res.Message)
	}
}

// The same entry, unreadable, on two consecutive rounds is not an event. Before
// the fix it was one on the first round and never again.
func TestRatelimitDoesNotAlertOnAnUnreadableEntryTwice(t *testing.T) {
	fake := newFakeRedis()
	fake.lists["RL_LOG"] = []string{`{"qid":"AAA111"}`}
	p := NewRatelimit("ratelimit", fake)

	runProbe(t, p) // the seeding round

	fake.lists["RL_LOG"] = []string{"<html>502 Bad Gateway</html>"}
	first := runProbe(t, p)
	if first.Status != health.StatusCritical {
		t.Fatalf("a new unreadable entry: status = %v (%s), want CRITICAL — it is a change",
			first.Status, first.Message)
	}

	second := runProbe(t, p)
	if second.Status != health.StatusOK {
		t.Errorf("the same unreadable entry again: status = %v (%s), want OK",
			second.Status, second.Message)
	}
}
