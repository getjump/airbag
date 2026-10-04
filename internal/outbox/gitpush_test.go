package outbox

import (
	"strings"
	"testing"
)

func TestGitPush(t *testing.T) {
	ok := [][]string{
		{"git", "push"},
		{"git", "push", "origin", "main"},
		{"git", "push", "-u", "origin", "feature/retry"},
		{"git", "push", "--force-with-lease", "origin", "HEAD:refs/heads/x"},
		{"git", "push", "https://github.com/acme/api.git", "main"},
	}
	for _, argv := range ok {
		if _, err := GitPush(argv); err != nil {
			t.Errorf("%v: unexpected error %v", argv, err)
		}
	}
	bad := [][]string{
		{"rm", "-rf", "/"},
		{"git", "status"},
		{"git", "push", "--receive-pack=sh -c evil", "origin"},
		{"git", "push", "--exec=evil", "origin"},
		{"git", "push", "-o", "x", "origin"},
		{"git", "push", "ext::sh -c evil", "main"},
		{"git", "push", "origin", "main;rm -rf ~"},
		{"git", "push", "origin", "$(evil)"},
	}
	for _, argv := range bad {
		if _, err := GitPush(argv); err == nil {
			t.Errorf("%v: accepted", strings.Join(argv, " "))
		}
	}
}

func TestLine(t *testing.T) {
	got := Line([]string{"gh", "pr", "create", "--title", "Fix retry", "--body", "it's", ""})
	if want := `gh pr create --title 'Fix retry' --body 'it'\''s' ''`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
