package effects

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		if _, err := l.db.ExecContext(t.Context(), q); err == nil {
			t.Errorf("%s succeeded on an append-only log", q)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	db, _ := sql.Open("sqlite", path)
	defer func() { _ = db.Close() }()
	var n int
	_ = db.QueryRowContext(t.Context(), `SELECT count(*) FROM events`).Scan(&n)
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
	_, err = db.ExecContext(t.Context(), `CREATE TABLE events (id INTEGER PRIMARY KEY, t TEXT, kind TEXT, target TEXT, verdict TEXT, reason TEXT, predict TEXT);
 INSERT INTO events VALUES (1, '2026-10-04T00:00:00Z', 'proc.exec', 'old', 'allow', '', '[]')`)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	old, err := Read(path)
	if err != nil || len(old) != 1 || old[0].Source != "" {
		t.Fatalf("legacy read: %+v %v", old, err)
	}
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if err := l.AddChecked(Effect{Kind: "proc.exec", Target: "/usr/bin/python3", Source: "seccomp", PID: 7, Detail: "execve", Argv: []string{"python3", "script.py"}, Verdict: "deny"}); err != nil {
		t.Fatal(err)
	}
	es, err := Read(path)
	if err != nil || len(es) != 2 || es[1].PID != 7 || len(es[1].Argv) != 2 {
		t.Fatalf("roundtrip: %+v %v", es, err)
	}
	for _, q := range []string{`UPDATE event_context SET data='{}'`, `DELETE FROM event_context`} {
		if _, err := l.db.ExecContext(t.Context(), q); err == nil {
			t.Fatal("audit context is mutable", q)
		}
	}
}

func TestBatchAtomicAndFullDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	var syncMode int
	if err := l.db.QueryRowContext(t.Context(), "PRAGMA synchronous").Scan(&syncMode); err != nil || syncMode != 2 {
		t.Fatalf("synchronous=%d err=%v", syncMode, err)
	}
	// Fail the second insert after the first event/context were written.
	if _, err := l.db.ExecContext(t.Context(), `CREATE TRIGGER reject_test BEFORE INSERT ON events WHEN NEW.target='reject' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	batch := []Effect{{Kind: "fs.read", Target: "first", Source: "fuse", PID: 12}, {Kind: "fs.write", Target: "reject", Source: "fuse", PID: 13}}
	if err := l.AddBatchChecked(batch); err == nil {
		t.Fatal("partial batch accepted")
	}
	got, err := Read(path)
	if err != nil || len(got) != 0 {
		t.Fatalf("partial commit: %+v %v", got, err)
	}
	var contexts int
	if err := l.db.QueryRowContext(t.Context(), "SELECT count(*) FROM event_context").Scan(&contexts); err != nil || contexts != 0 {
		t.Fatalf("orphan context: %d %v", contexts, err)
	}
	batch[1].Target = "second"
	if err := l.AddBatchChecked(batch); err != nil {
		t.Fatal(err)
	}
	got, err = Read(path)
	if err != nil || len(got) != 2 || got[0].Target != "first" || got[1].PID != 13 {
		t.Fatalf("batch roundtrip: %+v %v", got, err)
	}
}

// A context row adds source, PID, detail and argv to its event and
// nothing else: one that names a verdict or kind does not change them.
func TestRuntimeContextCannotChangeVerdict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if err := l.AddChecked(Effect{Kind: "fs.write", Target: "/w/protected", Verdict: "deny", Source: "fuse", PID: 9}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.ExecContext(t.Context(), `INSERT INTO events (t, kind, target, verdict) VALUES ('2026-10-05T00:00:00Z', 'fs.write', '/w/other', 'deny');
INSERT INTO event_context (id, data) VALUES (last_insert_rowid(), '{"source":"fuse","verdict":"allow","kind":"fs.read","target":"/w/x"}')`); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil || len(got) != 2 {
		t.Fatalf("read: %+v %v", got, err)
	}
	if got[0].Source != "fuse" || got[0].PID != 9 {
		t.Errorf("context lost: %+v", got[0])
	}
	if e := got[1]; e.Verdict != "deny" || e.Kind != "fs.write" || e.Target != "/w/other" || e.Source != "fuse" {
		t.Errorf("context changed the event: %+v", e)
	}
}

// Runtime refusals go through the same meter as every refusal; every
// allowed runtime entry is written with its context.
func TestRuntimeRefusalsMetered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	batch := make([]Effect, 0, refuseBurst+15)
	for range refuseBurst + 5 {
		batch = append(batch, Effect{Kind: "proc.exec", Target: "/usr/bin/x", Verdict: "deny", Source: "seccomp", PID: 7, Argv: []string{"x"}})
	}
	for range 10 {
		batch = append(batch, Effect{Kind: "fs.read", Target: "/w/f", Verdict: "allow", Source: "fuse", PID: 8})
	}
	if err := l.AddBatchChecked(batch); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	deny, allow, dropped := 0, 0, 0
	for _, e := range got {
		switch {
		case e.Kind == Dropped:
			dropped += DroppedCount(e)
		case e.Verdict == "deny" && e.Source == "seccomp" && e.PID == 7 && len(e.Argv) == 1:
			deny++
		case e.Verdict == "allow" && e.Source == "fuse" && e.PID == 8:
			allow++
		}
	}
	if deny != refuseBurst || dropped != 5 || allow != 10 {
		t.Fatalf("deny %d (want %d), dropped %d (want 5), allow %d (want 10)", deny, refuseBurst, dropped, allow)
	}
}

// Past the burst, refused entries (deny, ask) of a kind are held to the
// rate and the
// rest are counted; the count is written before the kind's next entry
// and when the log closes. Other entries and other kinds are written.
func TestRefusalsMetered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	deny := Effect{Kind: "net.egress", Target: "x:443", Verdict: "deny", Reason: "host not in allowlist"}
	batch := make([]Effect, refuseBurst+5)
	for i := range batch {
		batch[i] = deny
	}
	if err := l.AddAll(batch); err != nil {
		t.Fatal(err)
	}
	l.Add(Effect{Kind: "net.egress", Target: "y:443", Verdict: "allow"})
	l.Add(Effect{Kind: "proc.exec", Target: "rm", Verdict: "deny"})
	l.Add(Effect{Kind: "net.egress", Target: "x:443", Verdict: "ask", Reason: "ask-rule"})
	now = now.Add(time.Second)
	l.Add(deny)
	for range refuseRate + 3 {
		l.Add(deny)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	var drops []string
	for _, e := range got {
		count[e.Kind+" "+e.Verdict]++
		if e.Kind == Dropped {
			drops = append(drops, e.Target+": "+e.Reason)
		}
	}
	if n := count["net.egress deny"]; n != refuseBurst+refuseRate {
		t.Errorf("%d deny entries written, want %d", n, refuseBurst+refuseRate)
	}
	if count["net.egress allow"] != 1 || count["proc.exec deny"] != 1 {
		t.Errorf("counts %v", count)
	}
	want := []string{
		"net.egress: 6 net.egress refusals not logged: more than 50 a second",
		"net.egress: 4 net.egress refusals not logged: more than 50 a second",
	}
	if strings.Join(drops, "\n") != strings.Join(want, "\n") {
		t.Errorf("dropped entries:\n%s", strings.Join(drops, "\n"))
	}
	// The first count comes right before the entry that follows the gap.
	for i, e := range got {
		if e.Kind == Dropped {
			if i+1 < len(got) && got[i+1].Kind != "net.egress" {
				t.Errorf("entry after the count: %+v", got[i+1])
			}
			break
		}
	}
}

// Past maxMetered kinds, the rest share one meter.
func TestRefusalKindsBounded(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "effects.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	for i := range 3 * maxMetered {
		l.Add(Effect{Kind: fmt.Sprintf("k%d", i), Verdict: "deny"})
	}
	if len(l.refusals) != maxMetered+1 {
		t.Errorf("%d meters", len(l.refusals))
	}
}

// Once a flood stops, its count goes in with the next write of any
// kind a second or more later, so a review of a running session sees
// it before the log closes.
func TestDroppedCountedAfterFlood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	es := make([]Effect, refuseBurst+10)
	for i := range es {
		es[i] = Effect{Kind: "net.egress", Target: "x:443", Verdict: "deny"}
	}
	if err := l.AddAll(es); err != nil {
		t.Fatal(err)
	}
	now = now.Add(1500 * time.Millisecond)
	if err := l.AddAll([]Effect{{Kind: "tool.call", Target: "Read", Verdict: "allow"}}); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range got {
		n += DroppedCount(e)
	}
	if n != 10 {
		t.Fatalf("%d counted before Close, want 10", n)
	}
}

// A write after Close fails rather than going nowhere unnoticed, and a
// second Close is harmless.
func TestAddAllAfterClose(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "effects.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.AddAll([]Effect{{Kind: "secret.read", Target: ".env", Verdict: "taint"}}); err == nil {
		t.Fatal("a write after Close reported success")
	}
	l.Add(Effect{Kind: "x"}) // and does not panic
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

// A batch that does not commit leaves the meters as they were: its
// entries took no tokens and its counts are still held, for a retry and
// for Close.
func TestMeterRestoredOnFailedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	deny := Effect{Kind: "net.egress", Target: "x:443", Verdict: "deny"}
	es := make([]Effect, refuseBurst+3)
	for i := range es {
		es[i] = deny
	}
	if err := l.AddAll(es); err != nil {
		t.Fatal(err)
	}
	// Another writer holds the database past the busy timeout.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.ExecContext(t.Context(), "PRAGMA busy_timeout = 0"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	before := *l.refusals["net.egress"]
	if err := l.AddAll([]Effect{deny}); err == nil {
		t.Fatal("a write under another writer's lock succeeded")
	}
	if got := *l.refusals["net.egress"]; got != before {
		t.Errorf("meter changed by a failed write: %+v, was %+v", got, before)
	}
	if err := l.Close(); err == nil {
		t.Error("Close reported no error for a count it could not write")
	}
	if l.refusals["net.egress"].dropped != 3 {
		t.Errorf("held-back count cleared: %d", l.refusals["net.egress"].dropped)
	}
	if _, err := conn.ExecContext(t.Context(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
}
