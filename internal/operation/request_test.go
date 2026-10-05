package operation

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/quick"
)

func validRequest() Request {
	return Request{Schema: Schema, Kind: CreatePullRequest, PullRequest: &PullRequest{
		Repository: "getjump/airbag", Base: "main", Head: "feature/work", HeadCommit: strings.Repeat("a", 40), Title: "Fix retry", Body: "Reviewed body\n"}}
}

func TestDigestBindsEveryField(t *testing.T) {
	r := validRequest()
	digest, err := r.Digest()
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*PullRequest){
		func(p *PullRequest) { p.Repository = "other/project" },
		func(p *PullRequest) { p.Base = "release" },
		func(p *PullRequest) { p.Head = "feature/other" },
		func(p *PullRequest) { p.HeadCommit = strings.Repeat("b", 40) },
		func(p *PullRequest) { p.Title += "!" },
		func(p *PullRequest) { p.Body += "!" },
		func(p *PullRequest) { p.Draft = true },
	}
	for _, mutate := range mutations {
		changed := validRequest()
		mutate(changed.PullRequest)
		got, err := changed.Digest()
		if err != nil || got == digest {
			t.Fatalf("changed request retained approval digest: %s %v", got, err)
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var restored Request
	if err := json.Unmarshal(b, &restored); err != nil {
		t.Fatal(err)
	}
	if got, err := restored.Digest(); err != nil || got != digest {
		t.Fatalf("round trip changed digest: %s %v", got, err)
	}
}

func TestRequestRejectsAmbiguousTargets(t *testing.T) {
	for _, s := range []string{"", "-main", "main~1", "main^{commit}", "@", "@{1}", "a..b", "owner:branch", "a.lock", "a/.b", "a//b", "/main", "main/", "a%20b\n", "a\x00b", "a\\b"} {
		if ValidBranch(s) {
			t.Errorf("accepted branch %q", s)
		}
	}
	for _, s := range []string{"main", "feature/one", "release-1.0"} {
		if !ValidBranch(s) {
			t.Errorf("rejected branch %q", s)
		}
	}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.Schema = "future" }, func(r *Request) { r.Kind = "shell.exec" },
		func(r *Request) { r.PullRequest = nil }, func(r *Request) { r.PullRequest.Repository = "https://evil/repo" },
		func(r *Request) { r.PullRequest.HeadCommit = "HEAD" }, func(r *Request) { r.PullRequest.Title = "a\nb" },
		func(r *Request) { r.PullRequest.Body = strings.Repeat("x", MaxBody+1) },
	} {
		r := validRequest()
		mutate(&r)
		if _, err := r.Digest(); err == nil {
			t.Errorf("accepted invalid request %+v", r)
		}
	}
}

func TestPureReducerTerminalLaw(t *testing.T) {
	states := []State{Pending, Approved, Running, Completed, Failed, Rejected, Unknown, "bogus"}
	if err := quick.Check(func(n uint8) bool {
		next := states[int(n)%len(states)]
		for _, terminal := range []State{Completed, Failed, Rejected, Unknown} {
			got, err := Reduce(terminal, next)
			if err == nil || got != terminal {
				return false
			}
		}
		return true
	}, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
	current := Pending
	for _, next := range []State{Approved, Running, Unknown} {
		var err error
		current, err = Reduce(current, next)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Reduce(Pending, Running); err == nil {
		t.Fatal("unapproved request started")
	}
}

func FuzzRequestDigest(f *testing.F) {
	f.Add("feature/work", "hello", "body")
	f.Add("-option", "title", "\x00")
	f.Fuzz(func(t *testing.T, head, title, body string) {
		r := validRequest()
		r.PullRequest.Head, r.PullRequest.Title, r.PullRequest.Body = head, title, body
		before, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		a, ae := r.Digest()
		b, be := r.Digest()
		after, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if a != b || (ae == nil) != (be == nil) || string(before) != string(after) {
			t.Fatal("digest is not pure")
		}
	})
}

func TestBodyFitsGitHub(t *testing.T) {
	r := validRequest()
	r.PullRequest.Body = strings.Repeat("é", MaxBodyChars)
	if _, err := r.Digest(); err != nil {
		t.Fatalf("refused a body GitHub accepts: %v", err)
	}
	r.PullRequest.Body += "é"
	if _, err := r.Digest(); err == nil {
		t.Fatal("accepted a body GitHub refuses")
	}
}
