// Package effects is the append-only effect log of a session, a SQLite
// database with one table. Triggers refuse updates and deletes, so the
// log is the source of truth for review and audit:
//
//	sqlite3 /var/tmp/airbag-$UID/s-…/effects.db 'select kind, count(*) from events group by 1'
package effects

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/getjump/airbag/audit"
)

// Effect retains the storage API spelling of a shared audit record.
type Effect = audit.Event

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
	mu     sync.Mutex
	db     *sql.DB
	closed bool
	// refusals meter the refused entries (deny, ask) of each kind (Add).
	refusals map[string]*meter
	now      func() time.Time
}

// The agent decides how many refusals it provokes (a deny, or an ask
// it retries), and each is a row on the host's disk. Past a burst of
// refuseBurst, the refused entries of one kind are written at most
// refuseRate a second; those not written are counted, and the count
// goes in as a log.dropped entry before that kind's next written one,
// with any later write a second or more after its last count (so a
// review of a running session sees it), and when the log closes. Every
// other entry is written: allowed ones are what the agent did.
const (
	refuseBurst = 1000
	refuseRate  = 50
	// maxMetered kinds have a meter each; the rest share one.
	maxMetered = 64
)

// Dropped is the kind of the entry that counts the refused entries a
// meter kept out of the log; its target is their kind.
const Dropped = "log.dropped"

type meter struct {
	tokens  float64
	last    time.Time
	dropped int
	counted time.Time // when the count last went in
}

// take reports whether one more entry may be written at t.
func (m *meter) take(t time.Time) bool {
	m.tokens = min(refuseBurst, m.tokens+t.Sub(m.last).Seconds()*refuseRate)
	m.last = t
	if m.tokens < 1 {
		m.dropped++
		return false
	}
	m.tokens--
	return true
}

func Open(path string) (*Log, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Log{db: db, refusals: map[string]*meter{}, now: time.Now}, nil
}

// Add writes e, unless it is a refusal past its kind's rate. A failure
// to write is not reported; AddAll reports it.
func (l *Log) Add(e Effect) { _ = l.AddAll([]Effect{e}) }

var errClosed = errors.New("effect log closed")

// AddAll writes es in one transaction: a batch costs one sync to disk,
// not one each. It reports whether they were written; a refusal past
// its rate is counted, not an error.
func (l *Log) AddAll(es []Effect) error {
	if len(es) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errClosed
	}
	// The meters change as the entries go in; if the transaction does
	// not commit, none of it happened.
	saved := make(map[string]meter, len(l.refusals))
	for k, m := range l.refusals {
		saved[k] = *m
	}
	err := l.addAll(es)
	if err != nil {
		for k, m := range l.refusals {
			if v, ok := saved[k]; ok {
				*m = v
			} else {
				delete(l.refusals, k)
			}
		}
	}
	return err
}

// addAll is AddAll's transaction. l.mu is held.
func (l *Log) addAll(es []Effect) error {
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := l.add(tx, e); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	now := l.now()
	for kind, m := range l.refusals {
		if m.dropped > 0 && now.Sub(m.counted) >= time.Second {
			if err := l.count(tx, kind, m, now); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}
	return tx.Commit()
}

// count writes the count of m's entries not written. l.mu is held.
func (l *Log) count(tx *sql.Tx, kind string, m *meter, now time.Time) error {
	if err := insert(tx, dropped(kind, m.dropped, now)); err != nil {
		return err
	}
	m.dropped, m.counted = 0, now
	return nil
}

// add writes e through tx, with the count of the entries of its kind
// that were not, if any. l.mu is held.
func (l *Log) add(tx *sql.Tx, e Effect) error {
	now := l.now()
	if e.Time.IsZero() {
		e.Time = now
	}
	if e.Verdict == "deny" || e.Verdict == "ask" {
		key := e.Kind
		if _, ok := l.refusals[key]; !ok && len(l.refusals) >= maxMetered {
			key = ""
		}
		m := l.refusals[key]
		if m == nil {
			m = &meter{tokens: refuseBurst, last: now, counted: now}
			l.refusals[key] = m
		}
		if !m.take(now) {
			return nil
		}
		if m.dropped > 0 {
			if err := l.count(tx, key, m, now); err != nil {
				return err
			}
		}
	}
	return insert(tx, e)
}

func dropped(kind string, n int, t time.Time) Effect {
	what := kind
	if what == "" {
		what = "other kinds'"
	}
	return Effect{Time: t, Kind: Dropped, Target: kind,
		Reason: fmt.Sprintf("%d %s refusals not logged: more than %d a second", n, what, refuseRate)}
}

// DroppedCount is how many refused entries a Dropped entry counts.
func DroppedCount(e Effect) int {
	var n int
	if e.Kind == Dropped {
		_, _ = fmt.Sscanf(e.Reason, "%d ", &n)
	}
	return n
}

// RefuseRate is how many refused entries of a kind a second the log
// keeps past its burst.
const RefuseRate = refuseRate

func insert(tx *sql.Tx, e Effect) error {
	pred := []byte("[]")
	if e.Predict != nil {
		if b, err := json.Marshal(e.Predict); err == nil {
			pred = b
		}
	}
	_, err := tx.ExecContext(context.Background(), `INSERT INTO events (t, kind, target, verdict, reason, predict) VALUES (?, ?, ?, ?, ?, ?)`,
		e.Time.UTC().Format(time.RFC3339Nano), e.Kind, e.Target, e.Verdict, e.Reason, string(pred))
	return err
}

// Close writes the counts of the refused entries still held back, then
// closes the database; later writes fail. It reports a count it could
// not write.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var es []Effect
	for kind, m := range l.refusals {
		if m.dropped > 0 {
			es = append(es, dropped(kind, m.dropped, l.now()))
		}
	}
	var err error
	if len(es) > 0 {
		if err = writeAll(l.db, es); err == nil {
			for _, m := range l.refusals {
				m.dropped = 0
			}
		}
	}
	return errors.Join(err, l.db.Close())
}

func writeAll(db *sql.DB, es []Effect) error {
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := insert(tx, e); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

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
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(context.Background(), `SELECT t, kind, target, verdict, reason, predict FROM events ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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
