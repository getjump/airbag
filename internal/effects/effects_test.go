package effects

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestAppendOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Add(Effect{Kind: "net.egress", Target: "a:443", Verdict: "allow"})
	l.Add(Effect{Kind: "proc.exec", Target: "rm -rf x", Verdict: "allow", Predict: []string{"fs.delete x (recursive)"}})

	got, err := Read(path) // while the writer is open
	if err != nil || len(got) != 2 || got[1].Predict[0] != "fs.delete x (recursive)" || got[0].Predict != nil {
		t.Fatalf("got %+v %v", got, err)
	}
	for _, q := range []string{`UPDATE events SET verdict = 'deny'`, `DELETE FROM events`} {
		if _, err := l.db.Exec(q); err == nil {
			t.Errorf("%s succeeded on an append-only log", q)
		}
	}
	l.Close()

	db, _ := sql.Open("sqlite", path)
	defer db.Close()
	var n int
	_ = db.QueryRow(`SELECT count(*) FROM events`).Scan(&n)
	if n != 2 {
		t.Fatalf("rows = %d", n)
	}
}

func TestLegacyLogAndRuntimeContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE events (id INTEGER PRIMARY KEY, t TEXT, kind TEXT, target TEXT, verdict TEXT, reason TEXT, predict TEXT);
 INSERT INTO events VALUES (1, '2026-10-04T00:00:00Z', 'proc.exec', 'old', 'allow', '', '[]')`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	old, err := Read(path)
	if err != nil || len(old) != 1 || old[0].Source != "" {
		t.Fatalf("legacy read: %+v %v", old, err)
	}
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if err := log.AddChecked(Effect{Kind: "proc.exec", Target: "/usr/bin/python3", Source: "seccomp", PID: 7, Detail: "execve", Argv: []string{"python3", "script.py"}, Verdict: "deny"}); err != nil {
		t.Fatal(err)
	}
	es, err := Read(path)
	if err != nil || len(es) != 2 || es[1].PID != 7 || len(es[1].Argv) != 2 {
		t.Fatalf("roundtrip: %+v %v", es, err)
	}
	for _, q := range []string{`UPDATE event_context SET data='{}'`, `DELETE FROM event_context`} {
		if _, err := log.db.Exec(q); err == nil {
			t.Fatal("audit context is mutable", q)
		}
	}
}
