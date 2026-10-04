package policy

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

// Decisions on a request. A request is decided once: a trigger refuses
// changing a decision, so what the human answered stays on record.
const (
	Pending  = ""
	Approved = "approved"
	Denied   = "denied"
)

// Request is an "ask": an effect a rule holds until the human decides.
type Request struct {
	ID       string    `json:"id"`
	Key      string    `json:"key"`
	Rule     string    `json:"rule"`
	What     string    `json:"what"`
	Message  string    `json:"message,omitempty"`
	Created  time.Time `json:"created"`
	Decision string    `json:"decision,omitempty"`
}

const asksSchema = `
CREATE TABLE IF NOT EXISTS asks (
	id       TEXT PRIMARY KEY,
	key      TEXT NOT NULL UNIQUE,
	rule     TEXT NOT NULL,
	what     TEXT NOT NULL,
	message  TEXT NOT NULL DEFAULT '',
	created  TEXT NOT NULL,
	decision TEXT NOT NULL DEFAULT '',
	decided  TEXT NOT NULL DEFAULT ''
);
CREATE TRIGGER IF NOT EXISTS asks_decided_once BEFORE UPDATE ON asks
	WHEN OLD.decision != '' BEGIN SELECT RAISE(ABORT, 'request already decided'); END;
CREATE TRIGGER IF NOT EXISTS asks_no_delete BEFORE DELETE ON asks
	BEGIN SELECT RAISE(ABORT, 'requests are kept'); END;
`

// Asks are the session's requests, in the session database.
type Asks struct{ db *sql.DB }

func OpenAsks(path string) (*Asks, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(asksSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &Asks{db: db}, nil
}

func (a *Asks) Close() error { return a.db.Close() }

// Open returns the request for key, creating it when there is none; new
// reports whether it was created now.
func (a *Asks) Open(key, rule, what, message string) (r Request, created bool, err error) {
	tx, err := a.db.Begin()
	if err != nil {
		return r, false, err
	}
	defer tx.Rollback()
	if r, err = scanAsk(tx.QueryRow(`SELECT id, key, rule, what, message, created, decision FROM asks WHERE key = ?`, key)); err == nil {
		return r, false, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return r, false, err
	}
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM asks`).Scan(&n); err != nil {
		return r, false, err
	}
	r = Request{ID: fmt.Sprintf("a-%d", n+1), Key: key, Rule: rule, What: what, Message: message, Created: time.Now()}
	if _, err := tx.Exec(`INSERT INTO asks (id, key, rule, what, message, created) VALUES (?, ?, ?, ?, ?, ?)`,
		r.ID, r.Key, r.Rule, r.What, r.Message, r.Created.UTC().Format(time.RFC3339Nano)); err != nil {
		return r, false, err
	}
	return r, true, tx.Commit()
}

// Get returns one request by ID.
func (a *Asks) Get(id string) (Request, error) {
	return scanAsk(a.db.QueryRow(`SELECT id, key, rule, what, message, created, decision FROM asks WHERE id = ?`, id))
}

// List returns all requests in the order they were made.
func (a *Asks) List() ([]Request, error) {
	rows, err := a.db.Query(`SELECT id, key, rule, what, message, created, decision FROM asks ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		r, err := scanAsk(rows)
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Decide records the human's decision on a pending request, or on every
// pending one when id is "all", and returns the requests it decided.
func (a *Asks) Decide(id, decision string) ([]Request, error) {
	if decision != Approved && decision != Denied {
		return nil, fmt.Errorf("decision %q: want %s or %s", decision, Approved, Denied)
	}
	all, err := a.List()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var done []Request
	for _, r := range all {
		if r.Decision != Pending || (id != "all" && r.ID != id) {
			continue
		}
		if _, err := a.db.Exec(`UPDATE asks SET decision = ?, decided = ? WHERE id = ? AND decision = ''`, decision, now, r.ID); err != nil {
			return done, err
		}
		r.Decision = decision
		done = append(done, r)
	}
	if len(done) == 0 {
		return nil, fmt.Errorf("no pending request %s", id)
	}
	return done, nil
}

type scanner interface{ Scan(...any) error }

func scanAsk(s scanner) (Request, error) {
	var r Request
	var created string
	if err := s.Scan(&r.ID, &r.Key, &r.Rule, &r.What, &r.Message, &created, &r.Decision); err != nil {
		return r, err
	}
	r.Created, _ = time.Parse(time.RFC3339Nano, created)
	return r, nil
}

// Approval is a standing answer: `airbag approve --always` records that
// a rule may let this effect through in this workspace from now on. The
// file is plain text; deleting an entry takes the approval back.
type Approval struct {
	Rule      string    `yaml:"rule"`
	Effect    string    `yaml:"effect"`
	Workspace string    `yaml:"workspace"`
	Added     time.Time `yaml:"added"`
}

const approvalsHeader = "# Standing approvals, added by `airbag approve --always`.\n# Delete an entry to take it back.\n"

// ApprovalsPath is where standing approvals live.
func ApprovalsPath(home string) string {
	return filepath.Join(home, ".config", "airbag", "approvals.yaml")
}

func LoadApprovals(path string) ([]Approval, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var out []Approval
	return out, yaml.Unmarshal(b, &out)
}

// AddApproval appends a standing approval, unless an equal one exists.
func AddApproval(path string, a Approval) error {
	all, err := LoadApprovals(path)
	if err != nil {
		return err
	}
	for _, x := range all {
		if x.Rule == a.Rule && x.Effect == a.Effect && x.Workspace == a.Workspace {
			return nil
		}
	}
	b, err := yaml.Marshal(append(all, a))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(approvalsHeader), b...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// standing reports whether a standing approval covers rule and effect
// in workspace.
func standing(path, workspace, rule, effect string) bool {
	if path == "" {
		return false
	}
	all, _ := LoadApprovals(path)
	for _, a := range all {
		if a.Rule == rule && a.Effect == effect && (a.Workspace == workspace || a.Workspace == "") {
			return true
		}
	}
	return false
}

// SplitAskID accepts "a-3", or "s-1f2e/a-3" naming the session too.
func SplitAskID(arg string) (session, id string) {
	if s, i, ok := strings.Cut(arg, "/"); ok {
		return s, i
	}
	return "", arg
}
