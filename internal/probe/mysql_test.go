package probe

import (
	"strings"
	"testing"

	"bodsch.me/mailcow-watchdog/internal/health"
)

// healthy is a status row for a replica that is keeping up.
func healthy() map[string]string {
	return map[string]string{
		colSQLRunning:    "Yes",
		colIORunning:     "Yes",
		colPrimaryHost:   "db-primary.example.org",
		colSecondsBehind: "0",
	}
}

func withColumn(key, value string) map[string]string {
	status := healthy()
	status[key] = value
	return status
}

func TestReplicationVerdicts(t *testing.T) {
	tests := []struct {
		name    string
		status  map[string]string
		want    health.Status
		mention string
	}{
		{
			name:    "replicating",
			status:  healthy(),
			want:    health.StatusOK,
			mention: "replicating from primary db-primary.example.org",
		},
		{
			// A server with no replication configured returns an empty result
			// set. The shell reported that as "unable to connect", which is why
			// the check is opt-in.
			name:    "replication not configured",
			status:  nil,
			want:    health.StatusCritical,
			mention: "no replication status",
		},
		{
			name:    "SQL thread is NULL",
			status:  withColumn(colSQLRunning, "NULL"),
			want:    health.StatusCritical,
			mention: "SQL thread reports NULL",
		},
		{
			name:    "SQL thread column absent",
			status:  withColumn(colSQLRunning, ""),
			want:    health.StatusCritical,
			mention: "SQL thread reports NULL",
		},
		{
			name:    "SQL thread stopped",
			status:  withColumn(colSQLRunning, "No"),
			want:    health.StatusCritical,
			mention: "SQL thread is not running",
		},
		{
			name:    "IO thread stopped",
			status:  withColumn(colIORunning, "No"),
			want:    health.StatusCritical,
			mention: "I/O thread is not running",
		},
		{
			// Connecting means the replica cannot reach its primary. The shell
			// treated it as an outright failure rather than a warning.
			name:    "IO thread cannot reach the primary",
			status:  withColumn(colIORunning, "Connecting"),
			want:    health.StatusCritical,
			mention: "cannot reach the primary",
		},
		{
			name:    "unexpected state",
			status:  withColumn(colIORunning, "Preparing"),
			want:    health.StatusUnknown,
			mention: "unexpected replication state",
		},
	}

	p := NewMySQLReplication("replica-status", nil)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := p.evaluate(tc.status)
			if res.Status != tc.want {
				t.Errorf("status = %v (%s), want %v", res.Status, res.Message, tc.want)
			}
			if !strings.Contains(res.Message, tc.mention) {
				t.Errorf("message = %q, want it to mention %q", res.Message, tc.mention)
			}
		})
	}
}

// MariaDB reports Yes/No, but the comparison is case-insensitive so a future
// spelling change cannot silently turn a healthy replica into an alert.
func TestReplicationComparisonIsCaseInsensitive(t *testing.T) {
	p := NewMySQLReplication("replica-status", nil)

	status := map[string]string{
		colSQLRunning:    "YES",
		colIORunning:     "yes",
		colPrimaryHost:   "db-primary.example.org",
		colSecondsBehind: "3",
	}
	if res := p.evaluate(status); res.Status != health.StatusOK {
		t.Errorf("status = %v (%s), want OK", res.Status, res.Message)
	}
}

// A replica that is up but has not reported a lag figure should still read as
// healthy rather than printing an empty number.
func TestReplicationMissingLagReadsAsNA(t *testing.T) {
	p := NewMySQLReplication("replica-status", nil)

	res := p.evaluate(withColumn(colSecondsBehind, ""))
	if res.Status != health.StatusOK {
		t.Fatalf("status = %v (%s), want OK", res.Status, res.Message)
	}
	if !strings.Contains(res.Message, "N/A seconds behind") {
		t.Errorf("message = %q, want the missing lag spelled out", res.Message)
	}
}

// The column names keep MariaDB's original spelling on purpose: MDEV-20601 added
// REPLICA as a statement synonym in 10.5.1 but left the result columns alone, so
// SHOW REPLICA STATUS still returns Slave_IO_Running. Renaming these would simply
// stop the probe from finding anything.
func TestStatusColumnNamesMatchMariaDB(t *testing.T) {
	want := map[string]string{
		colSQLRunning:    "Slave_SQL_Running",
		colIORunning:     "Slave_IO_Running",
		colPrimaryHost:   "Master_Host",
		colSecondsBehind: "Seconds_Behind_Master",
	}
	for got, expected := range want {
		if got != expected {
			t.Errorf("column constant = %q, want %q", got, expected)
		}
	}
}

func TestProbesWithoutADatabaseHandleAreUnknown(t *testing.T) {
	for _, p := range []Probe{
		NewMySQLPing("connect", nil),
		NewMySQLQuery("table-count", nil, "SELECT 1"),
		NewMySQLReplication("replica-status", nil),
	} {
		res := runProbe(t, p)
		if res.Status != health.StatusUnknown {
			t.Errorf("%s: status = %v (%s), want UNKNOWN", p.Name(), res.Status, res.Message)
		}
	}
}
