package outbox

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/getjump/airbag/operation"
)

func typedIntent() Intent {
	return Intent{Kind: KindPullRequest, Cwd: "/w", Request: &operation.Request{Schema: operation.Schema, Kind: KindPullRequest,
		PullRequest: &operation.PullRequest{Repository: "getjump/airbag", Base: "main", Head: "feature/work", HeadCommit: strings.Repeat("a", 40), Title: "Fix", Body: "body"}}}
}

func TestTypedApprovalSurvivesReopenAndIsSingleUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	in, err := b.Push(typedIntent())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Claim(in.ID, in.RequestDigest); err == nil {
		t.Fatal("claimed without approval")
	}
	changed := typedIntent()
	changed.Request.PullRequest.Body = "different"
	wrong, err := changed.Request.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Approve(in.ID, wrong); err == nil {
		t.Fatal("approved a different payload")
	}
	if err := b.Approve(in.ID, in.RequestDigest); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Claim(in.ID, in.RequestDigest); err != nil {
		t.Fatal(err)
	}
	if err := b.Claim(in.ID, in.RequestDigest); err == nil {
		t.Fatal("approval consumed twice")
	}
	in.Status = Unknown
	if err := b.Update(in); err != nil {
		t.Fatal(err)
	}
	if err := b.Approve(in.ID, in.RequestDigest); err == nil {
		t.Fatal("unknown result reapproved")
	}
	all, err := b.List()
	if err != nil || len(all) != 1 || all[0].Status != Unknown || all[0].Request.PullRequest.Body != "body" {
		t.Fatalf("reopen: %+v %v", all, err)
	}
}

func TestCompetingClaimsAndImmutablePayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "effects.db")
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	in, err := b.Push(typedIntent())
	if err != nil {
		t.Fatal(err)
	}
	in.Request.PullRequest.Title = "mutated caller memory"
	all, err := b.List()
	if err != nil || all[0].Request.PullRequest.Title != "Fix" {
		t.Fatalf("caller changed stored request: %+v %v", all, err)
	}
	if err := b.Approve(in.ID, in.RequestDigest); err != nil {
		t.Fatal(err)
	}
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, box := range []*Box{b, other} {
		wg.Add(1)
		go func() { defer wg.Done(); results <- box.Claim(in.ID, in.RequestDigest) }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("%d handlers claimed one grant", wins)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, query := range []string{`UPDATE intent_requests SET request = '{}'`, `DELETE FROM intent_requests`} {
		if _, err := db.ExecContext(context.Background(), query); err == nil {
			t.Fatalf("payload mutated: %s", query)
		}
	}
}

func TestTypedUpdateCannotBypassApproval(t *testing.T) {
	b, err := Open(filepath.Join(t.TempDir(), "effects.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	in, err := b.Push(typedIntent())
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{string(operation.Approved), Running, Done, Unknown} {
		in.Status = status
		if err := b.Update(in); err == nil {
			t.Errorf("Update bypassed lifecycle with %s", status)
		}
	}
	in.Status = Rejected
	if err := b.Update(in); err != nil {
		t.Fatal(err)
	}
}
