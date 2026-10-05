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
	l.AddAll(batch)
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
