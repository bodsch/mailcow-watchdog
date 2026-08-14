package probe

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// MySQL replaces check_mysql and check_mysql_query: it verifies the server
// answers and, when a query is configured, that the query succeeds.
//
// Both probes in watchdog.sh went through the shared mysqld.sock volume rather
// than TCP, which is why the connection carries no TLS (see client.cnf).
type MySQL struct {
	name  string
	db    *sql.DB
	query string
}

// NewMySQLPing returns a probe that only checks connectivity.
func NewMySQLPing(name string, db *sql.DB) *MySQL {
	return &MySQL{name: name, db: db}
}

// NewMySQLQuery returns a probe that runs query and discards its result. The
// original used "SELECT COUNT(*) FROM information_schema.tables", which touches
// the storage engines rather than just the connection handler.
func NewMySQLQuery(name string, db *sql.DB, query string) *MySQL {
	return &MySQL{name: name, db: db, query: query}
}

// Name implements Probe.
func (p *MySQL) Name() string { return p.name }

// Run implements Probe.
func (p *MySQL) Run(ctx context.Context) Result {
	if p.db == nil {
		return Unknown("%s: no database handle configured", p.name)
	}
	if err := p.db.PingContext(ctx); err != nil {
		return Critical("%s: cannot reach the database: %v", p.name, err)
	}
	if p.query == "" {
		return OK("%s: database is reachable", p.name)
	}

	var discard any
	switch err := p.db.QueryRowContext(ctx, p.query).Scan(&discard); {
	case err == nil, errors.Is(err, sql.ErrNoRows):
		return OK("%s: query succeeded", p.name)
	default:
		return Critical("%s: query failed: %v", p.name, err)
	}
}

// MySQLReplication reports whether this server is replicating from its primary.
//
// It replaces check_mysql_slavestatus.sh.
//
// watchdog.sh called that script without -w, -c or -m, so the delay thresholds
// and the "replication has not moved" heuristic never applied and the whole
// 223-line script reduced to the state machine below. Note that a server with no
// replication configured returns an empty result set, which the script reported
// as "Unable to connect" — that is why the check is opt-in via
// WATCHDOG_MYSQL_REPLICATION_CHECKS.
type MySQLReplication struct {
	name string
	db   *sql.DB
}

// NewMySQLReplication returns a replication status probe. The handle must be
// connected as a user holding REPLICATION CLIENT.
func NewMySQLReplication(name string, db *sql.DB) *MySQLReplication {
	return &MySQLReplication{name: name, db: db}
}

// Name implements Probe.
func (p *MySQLReplication) Name() string { return p.name }

// Run implements Probe.
func (p *MySQLReplication) Run(ctx context.Context) Result {
	if p.db == nil {
		return Unknown("%s: no database handle configured", p.name)
	}

	status, err := replicationStatus(ctx, p.db)
	if err != nil {
		return Critical("%s: cannot read the replication status: %v", p.name, err)
	}
	return p.evaluate(status)
}

// evaluate turns one status row into a verdict. It is separate from the query so
// the state machine can be tested without a database.
func (p *MySQLReplication) evaluate(status map[string]string) Result {
	if status == nil {
		return Critical("%s: the server reports no replication status at all", p.name)
	}

	sqlRunning := status[colSQLRunning]
	ioRunning := status[colIORunning]
	primary := status[colPrimaryHost]
	delay := status[colSecondsBehind]

	switch {
	case sqlRunning == "" || strings.EqualFold(sqlRunning, "NULL"):
		return Critical("%s: the replica's SQL thread reports NULL (%s)", p.name, colSQLRunning)
	case strings.EqualFold(sqlRunning, "No"):
		return Critical("%s: the replica's SQL thread is not running", p.name)
	case strings.EqualFold(ioRunning, "No"):
		return Critical("%s: the replica's I/O thread is not running", p.name)
	case strings.EqualFold(ioRunning, "Connecting"):
		// Connecting means the replica cannot reach its primary, which the
		// original also treated as an outright failure rather than a warning.
		return Critical("%s: the replica's I/O thread cannot reach the primary", p.name)
	case strings.EqualFold(sqlRunning, "Yes") && strings.EqualFold(ioRunning, "Yes"):
		return OK("%s: replicating from primary %s, %s seconds behind",
			p.name, orNA(primary), orNA(delay))
	default:
		return Unknown("%s: unexpected replication state (SQL thread %q, I/O thread %q)",
			p.name, sqlRunning, ioRunning)
	}
}

// The column names in the status row.
//
// These keep the older spelling on purpose. MariaDB added REPLICA as a synonym
// for SLAVE in its statements in 10.5.1 (MDEV-20601), but deliberately left the
// result columns alone for backwards compatibility — SHOW REPLICA STATUS returns
// Slave_IO_Running, not Replica_IO_Running. Renaming these constants' values
// would simply stop the probe from finding anything.
const (
	colSQLRunning    = "Slave_SQL_Running"
	colIORunning     = "Slave_IO_Running"
	colPrimaryHost   = "Master_Host"
	colSecondsBehind = "Seconds_Behind_Master"
)

// replicationStatus returns the first status row as a column/value map, or nil
// when replication is not configured. The column set differs between MariaDB
// versions, so the row is read dynamically.
//
// The statement stays SHOW SLAVE STATUS rather than the SHOW REPLICA STATUS
// alias: the alias needs MariaDB 10.5.1 or newer and returns exactly the same
// columns, so switching would buy nothing but would break the check on older
// installations. MariaDB has not deprecated the original spelling.
func replicationStatus(ctx context.Context, db *sql.DB) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, "SHOW SLAVE STATUS")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		return nil, rows.Err()
	}

	cells := make([]sql.NullString, len(cols))
	targets := make([]any, len(cols))
	for i := range cells {
		targets[i] = &cells[i]
	}
	if err := rows.Scan(targets...); err != nil {
		return nil, err
	}

	status := make(map[string]string, len(cols))
	for i, name := range cols {
		if cells[i].Valid {
			status[name] = cells[i].String
		} else {
			// A genuine SQL NULL, which the shell script saw as the literal
			// string "NULL" in the \G output.
			status[name] = "NULL"
		}
	}
	return status, rows.Err()
}

// GUID reads the installation identifier the external check reports upstream.
func GUID(ctx context.Context, db *sql.DB) (string, error) {
	var guid string
	err := db.QueryRowContext(ctx,
		"SELECT version FROM versions WHERE application = 'GUID'").Scan(&guid)
	if err != nil {
		return "", fmt.Errorf("reading the mailcow GUID: %w", err)
	}
	return guid, nil
}

func orNA(v string) string {
	if v == "" {
		return "N/A"
	}
	return v
}
