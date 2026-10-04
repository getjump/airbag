package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getjump/airbag/internal/models"
)

func TestLoadAndDecide(t *testing.T) {
	ws, home := t.TempDir(), t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".config", "airbag"), 0o755)
	_ = os.WriteFile(filepath.Join(home, ".config", "airbag", "airbag.yaml"), []byte(`
allow: [api.github.com]
rules:
  - name: ask-before-hooks
    when: effect.kind == "persist"
    verdict: ask
    message: hooks run outside the sandbox later
`), 0o644)
	_ = os.WriteFile(filepath.Join(ws, "airbag.yaml"), []byte(`
rules:
  - name: allow-persist-in-ci-dir
    when: effect.kind == "persist" && effect.target.startsWith(".ci/")
    verdict: allow
  - name: no-prod
    when: command.line.contains("--context prod")
    verdict: deny
    message: never touch prod
`), 0o644)
	p, err := Load(ws, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Allow) != 1 || len(p.Sources) != 3 {
		t.Fatalf("allow %v sources %v", p.Allow, p.Sources)
	}
	for _, tc := range []struct {
		in   Input
		want string
		rule string
	}{
		{Input{Effect: models.Effect{Kind: "persist", Target: ".git/config"}}, Ask, "ask-before-hooks"},
		// ask beats a more specific allow: a deny or ask anywhere wins
		{Input{Effect: models.Effect{Kind: "persist", Target: ".ci/hook"}}, Ask, "ask-before-hooks"},
		{Input{Effect: models.Effect{Kind: "opaque"}, Argv: []string{"kubectl", "--context", "prod", "apply"}}, Deny, "no-prod"},
		{Input{Effect: models.Effect{Kind: "net.egress", Detail: "publish"}}, Deny, "no-publish"},
		{Input{Effect: models.Effect{Kind: "fs.write", Target: "a.go"}}, Allow, ""},
	} {
		d := p.Decide(tc.in)
		if d.Verdict != tc.want || d.Rule != tc.rule {
			t.Errorf("%+v: got %+v, want %s/%s", tc.in, d, tc.want, tc.rule)
		}
	}
}

func TestBadRule(t *testing.T) {
	ws := t.TempDir()
	_ = os.WriteFile(filepath.Join(ws, "airbag.yaml"), []byte("rules:\n  - when: effect.kind\n    verdict: deny\n"), 0o644)
	if _, err := Load(ws, t.TempDir()); err == nil {
		t.Fatal("non-boolean rule accepted")
	}
}

func TestOnTaint(t *testing.T) {
	g := NewGate(&Policy{}, t.TempDir())
	var got []string
	g.OnTaint(func(src string) { got = append(got, src) })
	g.Taint(".env")
	if len(got) != 1 || got[0] != ".env" {
		t.Fatalf("OnTaint ran %v times before Taint returned", got)
	}
	g.Taint(".env.local")
	if len(got) != 1 || g.Tainted() != ".env" {
		t.Fatalf("second taint: callbacks %v, tainted %q", got, g.Tainted())
	}
}
