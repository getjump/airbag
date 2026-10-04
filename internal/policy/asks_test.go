package policy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/models"
)

func askGate(t *testing.T) (*Gate, string) {
	t.Helper()
	p := &Policy{}
	if err := p.add(Rule{Name: "ask-send", When: `effect.kind == "net.egress"`, Verdict: Ask}); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "s.db")
	g, err := NewGate(p, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return g, db
}

var send = Input{Effect: models.Effect{Kind: "net.egress", Target: "example.com", Detail: "POST"}}

func TestAskApproveDeny(t *testing.T) {
	g, db := askGate(t)
	var hooked []string
	g.OnAsk(func(r Request) { hooked = append(hooked, r.ID) })

	d, id := g.Check(send)
	if d.Verdict != Ask || id != "a-1" {
		t.Fatalf("first check: %+v %s", d, id)
	}
	if d, id2 := g.Check(send); d.Verdict != Ask || id2 != "a-1" || len(hooked) != 1 {
		t.Fatalf("same effect again: %+v %s, hooks %v", d, id2, hooked)
	}

	asks, _ := OpenAsks(db) // another process: the airbag CLI
	defer asks.Close()
	if _, err := asks.Decide("a-1", Denied); err != nil {
		t.Fatal(err)
	}
	if d, _ := g.Check(send); d.Verdict != Deny {
		t.Fatalf("after deny: %+v", d)
	}
	if _, err := asks.Decide("a-1", Approved); err == nil {
		t.Fatal("a decided request changed its decision")
	}
	if _, err := asks.db.Exec(`UPDATE asks SET decision = 'approved' WHERE id = 'a-1'`); err == nil {
		t.Fatal("the trigger let a decision change")
	}

	other := Input{Effect: models.Effect{Kind: "net.egress", Target: "other.com", Detail: "POST"}}
	g.Check(other)
	if _, err := asks.Decide("a-2", Approved); err != nil {
		t.Fatal(err)
	}
	if d, _ := g.Check(other); d.Verdict != Allow {
		t.Fatalf("after approve: %+v", d)
	}
}

func TestAskWait(t *testing.T) {
	g, db := askGate(t)
	g.AskWait = 3 * time.Second
	asks, _ := OpenAsks(db)
	defer asks.Close()
	go func() {
		time.Sleep(400 * time.Millisecond)
		_, _ = asks.Decide("a-1", Approved)
	}()
	start := time.Now()
	d, _ := g.Check(send)
	if d.Verdict != Allow || time.Since(start) > 2*time.Second {
		t.Fatalf("held request: %+v after %v", d, time.Since(start))
	}
}

func TestStandingApproval(t *testing.T) {
	g, _ := askGate(t)
	path := filepath.Join(t.TempDir(), "approvals.yaml")
	g.ApprovalsPath, g.Workspace = path, "/w"
	if err := AddApproval(path, Approval{Rule: "ask-send", Effect: send.Effect.String(), Workspace: "/w"}); err != nil {
		t.Fatal(err)
	}
	_ = AddApproval(path, Approval{Rule: "ask-send", Effect: send.Effect.String(), Workspace: "/w"}) // no duplicate
	all, _ := LoadApprovals(path)
	if len(all) != 1 {
		t.Fatalf("approvals: %+v", all)
	}
	if d, _ := g.Check(send); d.Verdict != Allow {
		t.Fatalf("standing approval ignored: %+v", d)
	}
	g.Workspace = "/elsewhere"
	if d, _ := g.Check(send); d.Verdict != Ask {
		t.Fatalf("approval leaked to another workspace: %+v", d)
	}
}
