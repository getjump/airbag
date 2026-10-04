package outbox

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/getjump/airbag/internal/effects"
)

func TestBox(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	// The outbox shares the session database with the effect log.
	log, err := effects.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	log.Add(effects.Effect{Kind: "net.egress", Target: "a:443"})

	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	one, err := b.Push(Intent{Kind: "git.push", Argv: []string{"git", "push", "origin", "main"}, Cwd: "/w"})
	if err != nil || one.ID != "i-1" || one.Status != Pending {
		t.Fatalf("push: %+v %v", one, err)
	}
	two, _ := b.Push(Intent{Kind: "git.push", Argv: []string{"git", "push"}, Cwd: "/w"})
	one.Status, one.Output = Done, "pushed"
	if err := b.Update(one); err != nil {
		t.Fatal(err)
	}
	if err := b.Update(Intent{ID: "i-9", Status: Done}); err == nil {
		t.Error("update of a missing intent succeeded")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	b, _ = Open(path) // reopen: state is on disk
	defer func() { _ = b.Close() }()
	got, err := b.List()
	if err != nil || len(got) != 2 {
		t.Fatalf("list: %+v %v", got, err)
	}
	if got[0].ID != "i-1" || got[0].Status != Done || got[0].Output != "pushed" || got[0].Argv[3] != "main" || got[0].Created.IsZero() {
		t.Errorf("i-1 = %+v", got[0])
	}
	if got[1].ID != two.ID || got[1].Status != Pending {
		t.Errorf("i-2 = %+v", got[1])
	}

	db, _ := sql.Open("sqlite", path)
	defer func() { _ = db.Close() }()
	var hist int
	_ = db.QueryRowContext(t.Context(), `SELECT count(*) FROM intent_status WHERE intent = 'i-1'`).Scan(&hist)
	if hist != 2 {
		t.Errorf("i-1 history has %d rows, want pending and done", hist)
	}
	for _, q := range []string{
		`UPDATE intents SET argv = '["git","push","evil"]'`,
		`DELETE FROM intents`,
		`UPDATE intent_status SET status = 'done'`,
		`DELETE FROM intent_status`,
	} {
		if _, err := db.ExecContext(t.Context(), q); err == nil {
			t.Errorf("%s succeeded", q)
		}
	}
	if effs, _ := effects.Read(path); len(effs) != 1 {
		t.Errorf("effect log disturbed: %+v", effs)
	}
}

// A deferred command keeps the files it runs on; a database from
// before that column existed opens and reads as before.
func TestFilesAndOldDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `CREATE TABLE intents (id TEXT PRIMARY KEY, kind TEXT NOT NULL, argv TEXT NOT NULL, cwd TEXT NOT NULL, created TEXT NOT NULL);
		CREATE TABLE intent_status (seq INTEGER PRIMARY KEY AUTOINCREMENT, intent TEXT NOT NULL, t TEXT NOT NULL, status TEXT NOT NULL, output TEXT NOT NULL DEFAULT '');
		INSERT INTO intents VALUES ('i-1', 'git.push', '["git","push"]', '/w', '2026-10-04T00:00:00Z');
		INSERT INTO intent_status (intent, t, status) VALUES ('i-1', '2026-10-04T00:00:00Z', 'pending');`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	two, err := b.Push(Intent{Kind: KindCmd, Argv: []string{"gh", "pr", "create"}, Cwd: "/w", Files: map[string]string{"notes.md": "abc"}})
	if err != nil || two.ID != "i-2" {
		t.Fatalf("push: %+v %v", two, err)
	}
	all, err := b.List()
	if err != nil || len(all) != 2 {
		t.Fatalf("list: %+v %v", all, err)
	}
	if all[0].Files != nil || all[1].Files["notes.md"] != "abc" || all[1].Kind != KindCmd {
		t.Fatalf("files: %+v", all)
	}
}
