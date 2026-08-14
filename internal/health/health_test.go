package health

import (
	"sync"
	"testing"
)

// The golden values were produced by running the original shell expression
//
//	$(( 200 * ${CURRENT} / ${TOTAL} % 2 + 100 * ${CURRENT} / ${TOTAL} ))
//
// in bash for the thresholds mailcow actually ships. If Percent ever drifts from
// these, the health bars in the mailcow UI change too.
func TestPercentMatchesShellArithmetic(t *testing.T) {
	golden := map[int][]int{
		1:  {0, 100},
		3:  {0, 33, 67, 100},
		5:  {0, 20, 40, 60, 80, 100},
		7:  {0, 14, 29, 43, 57, 71, 86, 100},
		8:  {0, 13, 25, 38, 50, 63, 75, 88, 100},
		12: {0, 8, 17, 25, 33, 42, 50, 58, 67, 75, 83, 92, 100},
		15: {0, 7, 13, 20, 27, 33, 40, 47, 53, 60, 67, 73, 80, 87, 93, 100},
		20: {0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95, 100},
	}
	for total, want := range golden {
		for current, expected := range want {
			if got := Percent(current, total); got != expected {
				t.Errorf("Percent(%d, %d) = %d, want %d", current, total, got, expected)
			}
		}
	}
}

func TestPercentEdgeCases(t *testing.T) {
	if got := Percent(1, 0); got != 0 {
		t.Errorf("Percent(1, 0) = %d, want 0 (no division by zero)", got)
	}
	if got := Percent(-3, 5); got != 0 {
		t.Errorf("Percent(-3, 5) = %d, want 0", got)
	}
}

// A clean round repays one error point but never pushes health above the
// threshold, and the trend reads +1 exactly as hpdiff did.
func TestRecordCleanRoundRepaysOnePoint(t *testing.T) {
	tr := New("nginx", 5)

	got := tr.Record(0)
	want := Snapshot{Service: "nginx", Threshold: 5, Remaining: 5, Trend: 0, Percent: 100}
	if got != want {
		t.Errorf("first clean round = %+v, want %+v", got, want)
	}

	tr.Record(2) // remaining 3
	got = tr.Record(0)
	if got.Remaining != 4 || got.Trend != 1 {
		t.Errorf("recovery round = %+v, want remaining 4 and trend +1", got)
	}
}

// Failures add the sum of the probes' Nagios exit codes, so a CRITICAL costs
// twice what a WARNING does.
func TestRecordWeightsByNagiosStatus(t *testing.T) {
	tests := []struct {
		name          string
		weight        int
		wantRemaining int
		wantTrend     int
	}{
		{"warning", int(StatusWarning), 7, -1},
		{"critical", int(StatusCritical), 6, -2},
		{"unknown", int(StatusUnknown), 5, -3},
		{"two criticals", 2 * int(StatusCritical), 4, -4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := New("dovecot", 8)
			got := tr.Record(tc.weight)
			if got.Remaining != tc.wantRemaining || got.Trend != tc.wantTrend {
				t.Errorf("Record(%d) = %+v, want remaining %d trend %d",
					tc.weight, got, tc.wantRemaining, tc.wantTrend)
			}
		})
	}
}

func TestRecordReportsDeadAtThreshold(t *testing.T) {
	tr := New("redis", 3)

	if s := tr.Record(int(StatusCritical)); s.Dead() {
		t.Fatalf("2 of 3 points spent should not be dead: %+v", s)
	}
	s := tr.Record(int(StatusCritical))
	if !s.Dead() {
		t.Fatalf("4 of 3 points spent should be dead: %+v", s)
	}
	// Health is clamped rather than going negative, and 0 remaining is 0%.
	if s.Remaining != 0 || s.Percent != 0 {
		t.Errorf("dead snapshot = %+v, want remaining 0 and percent 0", s)
	}
}

// Reset mirrors the shell returning from a check function, which re-entered it
// with a fresh err_count.
func TestResetRestoresFullBudget(t *testing.T) {
	tr := New("postfix", 8)
	tr.Record(6)
	tr.Reset()
	if s := tr.Snapshot(); s.Remaining != 8 || s.Percent != 100 {
		t.Errorf("after Reset = %+v, want full health", s)
	}
}

// This is the feature whose shell trap never fired: after restarting a container
// the supervisor repays two points so a recovering service is not restarted
// again immediately.
func TestHealRepaysTwoPoints(t *testing.T) {
	tr := New("sogo", 6)
	tr.Record(4)

	got := tr.Heal(2)
	if got.Remaining != 4 || got.Trend != 2 {
		t.Errorf("Heal(2) = %+v, want remaining 4 and trend +2", got)
	}
}

// The shell guarded with `[ ${err_count} -gt 1 ]`, so a single outstanding point
// was left alone. Keeping that avoids masking a service that fails every other
// round.
func TestHealLeavesASinglePointAlone(t *testing.T) {
	tr := New("sogo", 6)
	tr.Record(1)

	got := tr.Heal(2)
	if got.Remaining != 5 || got.Trend != 0 {
		t.Errorf("Heal(2) with one point outstanding = %+v, want no change", got)
	}
}

func TestHealNeverOvershoots(t *testing.T) {
	tr := New("sogo", 6)
	tr.Record(2)

	if got := tr.Heal(10); got.Remaining != 6 {
		t.Errorf("Heal(10) = %+v, want remaining clamped to 6", got)
	}
}

// A threshold of zero would make every check report its service dead before the
// first probe, restarting the container in a loop.
func TestNewRaisesZeroThreshold(t *testing.T) {
	tr := New("acme", 0)
	if tr.Threshold() != 1 {
		t.Errorf("Threshold() = %d, want 1", tr.Threshold())
	}
	if s := tr.Snapshot(); s.Dead() {
		t.Errorf("a fresh tracker must not be dead: %+v", s)
	}
}

func TestNegativeWeightIsTreatedAsSuccess(t *testing.T) {
	tr := New("mysql", 5)
	tr.Record(3)
	if got := tr.Record(-1); got.Remaining != 3 {
		t.Errorf("Record(-1) = %+v, want it to behave like a clean round", got)
	}
}

// Record runs on the check's goroutine while Heal runs on the supervisor's.
func TestConcurrentRecordAndHeal(t *testing.T) {
	tr := New("dovecot", 12)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); tr.Record(1) }()
		go func() { defer wg.Done(); tr.Heal(2) }()
	}
	wg.Wait()

	if s := tr.Snapshot(); s.Remaining < 0 || s.Remaining > 12 {
		t.Errorf("remaining health left its bounds: %+v", s)
	}
}

func TestStatusString(t *testing.T) {
	tests := map[Status]string{
		StatusOK:       "OK",
		StatusWarning:  "WARNING",
		StatusCritical: "CRITICAL",
		StatusUnknown:  "UNKNOWN",
		Status(9):      "INVALID",
	}
	for status, want := range tests {
		if got := status.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", status, got, want)
		}
	}
}
