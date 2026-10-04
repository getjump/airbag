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
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	db, _ := sql.Open("sqlite", path)
	defer func() { _ = db.Close() }()
	var n int
	_ = db.QueryRow(`SELECT count(*) FROM events`).Scan(&n)
	if n != 2 {
		t.Fatalf("rows = %d", n)
	}
}
