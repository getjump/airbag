package operation

import (
	"reflect"
	"strings"
	"testing"
)

func TestPRParserRefusesImplicitOrAdditionalAuthority(t *testing.T) {
	valid := []string{"gh", "pr", "create", "-R", "getjump/airbag", "-B", "main", "-H", "feature/work", "-t", "Fix", "-b", "reviewed"}
	for _, extra := range [][]string{{"--fill"}, {"--web"}, {"--reviewer", "someone"}, {"--repo", "other/repo"}, {"--draft=false"}, {"--body-file", "notes.md"}} {
		args := append(append([]string{}, valid...), extra...)
		if _, matched, err := ParsePullRequest(args); !matched || err == nil {
			t.Errorf("accepted ambiguous request: %q", args)
		}
	}
	for _, args := range [][]string{{"gh", "pr", "create"}, {"gh", "--hostname", "evil", "pr", "create"}, {"gh", "-R", "getjump/airbag", "pr", "create", "--fill"}} {
		if _, matched, err := ParsePullRequest(args); !matched || err == nil {
			t.Errorf("fell through: %q", args)
		}
	}
	if _, matched, err := ParsePullRequest([]string{"gh", "pr", "list"}); matched || err != nil {
		t.Fatal("captured unrelated command")
	}
	a, matched, err := ParsePullRequest(valid)
	if err != nil || !matched || a.PullRequest.Body != "reviewed" {
		t.Fatalf("explicit request: %+v %v", a, err)
	}
	global := append([]string{"gh", "--repo=getjump/airbag", "pr", "create"}, valid[5:]...)
	b, matched, err := ParsePullRequest(global)
	if err != nil || !matched || !reflect.DeepEqual(a, b) {
		t.Fatalf("global --repo changed request: %+v %v", b, err)
	}
}

func TestPreviewIsFrozenAndDeterministic(t *testing.T) {
	r := validRequest()
	p, err := r.Preview()
	if err != nil {
		t.Fatal(err)
	}
	other, err := r.Preview()
	if err != nil || !reflect.DeepEqual(p, other) {
		t.Fatal("preview is not deterministic")
	}
	r.PullRequest.Body = "later"
	if p.Request.PullRequest.Body != "Reviewed body\n" || p.BodyDigest != Hash([]byte("Reviewed body\n")) {
		t.Fatal("preview shares mutable producer state")
	}
	if p.Authority.Resource != "getjump/airbag" || p.Authority.Permission != "pull_requests:write" {
		t.Fatalf("wrong required authority: %+v", p.Authority)
	}
}

func FuzzPRArguments(f *testing.F) {
	f.Add("--fill")
	f.Add("--body=body")
	f.Fuzz(func(t *testing.T, suffix string) {
		args := append([]string{"gh", "pr", "create"}, strings.Split(suffix, "\x00")...)
		before := append([]string{}, args...)
		_, matched, _ := ParsePullRequest(args)
		if !matched || !reflect.DeepEqual(args, before) {
			t.Fatal("parser changed producer input or let create fall through")
		}
	})
}
