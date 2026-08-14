// Package health implements the error accounting that decides when a service
// counts as dead.
//
// The arithmetic is deliberately identical to the one watchdog.sh performed
// inline in all nineteen of its check loops, because the mailcow UI reads the
// resulting numbers straight out of Redis:
//
//	err_c_cur=${err_count}
//	<probe>; err_count=$(( ${err_count} + $? ))
//	[ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] \
//	    && err_count=$((${err_count} - 1)) diff_c=1
//	[ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
//	progress "${SERVICE}" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
//
// In words: a clean round pays one error point back (floored at zero), a failing
// round adds the probes' Nagios exit codes, and health is the remaining distance
// to the threshold. Summing exit codes means a CRITICAL (2) moves twice as fast
// towards a restart as a WARNING (1) — kept as-is, since the thresholds shipped
// in mailcow.conf are calibrated against it.
package health

import "sync"

// Status is a Nagios plugin exit code. Its numeric value doubles as the number
// of error points a failing probe contributes.
type Status int

// The four Nagios plugin states.
const (
	StatusOK       Status = 0
	StatusWarning  Status = 1
	StatusCritical Status = 2
	StatusUnknown  Status = 3
)

// String renders the conventional Nagios label.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusWarning:
		return "WARNING"
	case StatusCritical:
		return "CRITICAL"
	case StatusUnknown:
		return "UNKNOWN"
	default:
		return "INVALID"
	}
}

// Snapshot is the outcome of folding one round of probes into the tracker.
type Snapshot struct {
	// Service is the display name used in the Redis log and in metrics.
	Service string
	// Threshold is the error budget, mirrored as hptotal.
	Threshold int
	// Remaining is Threshold minus the accumulated errors, mirrored as hpnow.
	// It is clamped to zero and never exceeds Threshold.
	Remaining int
	// Trend is the change in remaining health: +1 after a clean round, negative
	// by the weight of the failures otherwise. Mirrored as hpdiff.
	Trend int
	// Percent is Remaining as a share of Threshold, using the original's
	// round-half-up integer arithmetic. Mirrored as lvl.
	Percent int
}

// Dead reports whether the error budget is exhausted and the supervisor should
// act on the service.
func (s Snapshot) Dead() bool { return s.Remaining <= 0 }

// Tracker accumulates error points for a single check.
//
// It is safe for concurrent use: Record runs on the check's own goroutine while
// Heal is called by the supervisor after a container restart.
type Tracker struct {
	service   string
	threshold int

	mu       sync.Mutex
	errCount int
}

// New returns a Tracker with a full error budget. A threshold below one is
// raised to one, since a zero budget would report the service dead before it
// was ever probed.
func New(service string, threshold int) *Tracker {
	if threshold < 1 {
		threshold = 1
	}
	return &Tracker{service: service, threshold: threshold}
}

// Service returns the display name.
func (t *Tracker) Service() string { return t.service }

// Threshold returns the error budget.
func (t *Tracker) Threshold() int { return t.threshold }

// Record folds one round of probe results into the error count and returns the
// resulting snapshot. weight is the sum of the round's Nagios exit codes; zero
// means every probe passed.
func (t *Tracker) Record(weight int) Snapshot {
	if weight < 0 {
		weight = 0
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	before := t.errCount
	switch {
	case weight > 0:
		t.errCount += weight
	case t.errCount > 0:
		// A clean round repays a single point, never dropping below zero.
		t.errCount--
	}

	return t.snapshot(before - t.errCount)
}

// Heal repays points after the supervisor has restarted the unhealthy container,
// so that a service which recovers is not immediately restarted again.
//
// watchdog.sh intended this as `kill -USR1`, but its trap body was written with
// double quotes, so ${err_count} expanded to 0 at trap-definition time and the
// reduction never happened. This is that feature, working.
func (t *Tracker) Heal(points int) Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	before := t.errCount
	// The shell guarded with `[ ${err_count} -gt 1 ]`, so a single outstanding
	// error point was deliberately left in place.
	if t.errCount > 1 {
		t.errCount -= points
		if t.errCount < 0 {
			t.errCount = 0
		}
	}
	return t.snapshot(before - t.errCount)
}

// Reset clears the error count. The supervisor calls it after acting on a dead
// service, matching the shell's behaviour of returning from the check function
// and re-entering it with a fresh err_count.
func (t *Tracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.errCount = 0
}

// Snapshot returns the current state without changing it.
func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshot(0)
}

// snapshot renders the current error count. The caller must hold the mutex.
func (t *Tracker) snapshot(trend int) Snapshot {
	remaining := t.threshold - t.errCount
	if remaining < 0 {
		remaining = 0
	}
	return Snapshot{
		Service:   t.service,
		Threshold: t.threshold,
		Remaining: remaining,
		Trend:     trend,
		Percent:   Percent(remaining, t.threshold),
	}
}

// Percent converts a health level into a percentage using the same integer
// arithmetic as watchdog.sh:
//
//	PERCENT=$(( 200 * ${CURRENT} / ${TOTAL} % 2 + 100 * ${CURRENT} / ${TOTAL} ))
//
// Bash evaluates *, / and % left to right, so this is ((200*current)/total)%2
// added to (100*current)/total — truncating division plus one point whenever the
// doubled quotient is odd, i.e. round-half-up. Reproduced exactly so the values
// stored in WATCHDOG_LOG match what the mailcow UI has always displayed.
func Percent(current, total int) int {
	if total <= 0 {
		return 0
	}
	if current < 0 {
		current = 0
	}
	return (200*current/total)%2 + 100*current/total
}
