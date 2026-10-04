// Package outbox holds irreversible actions the agent asked for. They
// run on the host after the human approves them in review.
//
// Intents live in the session database next to the effect log. An
// intent is one immutable row; its status is a history of rows, the
// latest of which is current, so what was queued, rejected, run or
// failed, and when, stays on record:
//
//	sqlite3 effects.db 'select intent, t, status from intent_status'
package outbox

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const (
	Pending  = "pending"
	Done     = "done"
	Failed   = "failed"
	Rejected = "rejected"
)

type Intent struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"` // git.push
	Argv    []string  `json:"argv"`
	Cwd     string    `json:"cwd"`
	Created time.Time `json:"created"`
	Status  string    `json:"status"`
	Output  string    `json:"output,omitempty"`
}

const schema = `
CREATE TABLE IF NOT EXISTS intents (
	id      TEXT PRIMARY KEY,
	kind    TEXT NOT NULL,
	argv    TEXT NOT NULL,
	cwd     TEXT NOT NULL,
	created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS intent_status (
	seq    INTEGER PRIMARY KEY AUTOINCREMENT,
	intent TEXT NOT NULL REFERENCES intents(id),
	t      TEXT NOT NULL,
	status TEXT NOT NULL,
	output TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS intent_status_intent ON intent_status(intent);
CREATE TRIGGER IF NOT EXISTS intents_no_update BEFORE UPDATE ON intents
	BEGIN SELECT RAISE(ABORT, 'intents are immutable'); END;
CREATE TRIGGER IF NOT EXISTS intents_no_delete BEFORE DELETE ON intents
	BEGIN SELECT RAISE(ABORT, 'intents are immutable'); END;
CREATE TRIGGER IF NOT EXISTS intent_status_no_update BEFORE UPDATE ON intent_status
	BEGIN SELECT RAISE(ABORT, 'intent history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS intent_status_no_delete BEFORE DELETE ON intent_status
	BEGIN SELECT RAISE(ABORT, 'intent history is append-only'); END;
`

type Box struct {
	db *sql.DB
}

// Open opens the outbox in the session database at path.
func Open(path string) (*Box, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Box{db: db}, nil
}

func (b *Box) Close() error { return b.db.Close() }

// List returns all intents in the order they were queued, each with its
// current status.
func (b *Box) List() ([]Intent, error) {
	rows, err := b.db.Query(`
		SELECT i.id, i.kind, i.argv, i.cwd, i.created, s.status, s.output
		FROM intents i
		JOIN intent_status s ON s.seq = (SELECT max(seq) FROM intent_status WHERE intent = i.id)
		ORDER BY i.rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Intent
	for rows.Next() {
		var in Intent
		var argv, created string
		if err := rows.Scan(&in.ID, &in.Kind, &argv, &in.Cwd, &created, &in.Status, &in.Output); err != nil {
			return out, err
		}
		_ = json.Unmarshal([]byte(argv), &in.Argv)
		in.Created, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, in)
	}
	return out, rows.Err()
}

// Push queues an intent as pending and returns it with its ID.
func (b *Box) Push(in Intent) (Intent, error) {
	tx, err := b.db.Begin()
	if err != nil {
		return in, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM intents`).Scan(&n); err != nil {
		return in, err
	}
	in.ID = fmt.Sprintf("i-%d", n+1)
	in.Created = time.Now()
	in.Status, in.Output = Pending, ""
	argv, _ := json.Marshal(in.Argv)
	now := in.Created.UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`INSERT INTO intents (id, kind, argv, cwd, created) VALUES (?, ?, ?, ?, ?)`,
		in.ID, in.Kind, string(argv), in.Cwd, now); err != nil {
		return in, err
	}
	if _, err := tx.Exec(`INSERT INTO intent_status (intent, t, status) VALUES (?, ?, ?)`, in.ID, now, Pending); err != nil {
		return in, err
	}
	return in, tx.Commit()
}

// Update records a new status, and the command's output, for an intent.
// The intent itself does not change.
func (b *Box) Update(in Intent) error {
	res, err := b.db.Exec(`INSERT INTO intent_status (intent, t, status, output)
		SELECT id, ?, ?, ? FROM intents WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), in.Status, in.Output, in.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no intent " + in.ID)
	}
	return nil
}
