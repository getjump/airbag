// Package effects is the append-only effect log of a session, a SQLite
// database with one table. Triggers refuse updates and deletes, so the
// log is the source of truth for review and audit:
//
//	sqlite3 /var/tmp/airbag-$UID/s-…/effects.db 'select kind, count(*) from events group by 1'
package effects

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Effect is a fact: something changed or something left the machine.
type Effect struct {
	Time    time.Time `json:"t"`
	Kind    string    `json:"kind"`              // net.egress, intent.git_push, ...
	Target  string    `json:"target"`            // host:port, argv, path
	Verdict string    `json:"verdict,omitempty"` // allow, deny, defer
	Reason  string    `json:"reason,omitempty"`
	// Predict: what a command model expects this command to do.
	Predict []string `json:"predict,omitempty"`
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	t       TEXT NOT NULL,
	kind    TEXT NOT NULL,
	target  TEXT NOT NULL DEFAULT '',
	verdict TEXT NOT NULL DEFAULT '',
	reason  TEXT NOT NULL DEFAULT '',
	predict TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS events_kind ON events(kind);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
	BEGIN SELECT RAISE(ABORT, 'effect log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
	BEGIN SELECT RAISE(ABORT, 'effect log is append-only'); END;
`

type Log struct {
	mu sync.Mutex
	db *sql.DB
}

func Open(path string) (*Log, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Log{db: db}, nil
}

func (l *Log) Add(e Effect) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	pred, _ := json.Marshal(e.Predict)
	if e.Predict == nil {
		pred = []byte("[]")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.db.Exec(`INSERT INTO events (t, kind, target, verdict, reason, predict) VALUES (?, ?, ?, ?, ?, ?)`,
		e.Time.UTC().Format(time.RFC3339Nano), e.Kind, e.Target, e.Verdict, e.Reason, string(pred))
}

func (l *Log) Close() error { return l.db.Close() }

// Read returns all effects in order. It opens the database read-only,
// so it works while the session is still running.
func Read(path string) ([]Effect, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT t, kind, target, verdict, reason, predict FROM events ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Effect
	for rows.Next() {
		var e Effect
		var t, pred string
		if err := rows.Scan(&t, &e.Kind, &e.Target, &e.Verdict, &e.Reason, &pred); err != nil {
			return out, err
		}
		e.Time, _ = time.Parse(time.RFC3339Nano, t)
		_ = json.Unmarshal([]byte(pred), &e.Predict)
		if len(e.Predict) == 0 {
			e.Predict = nil
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
