package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/models"
	"github.com/getjump/airbag/internal/taint"
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

func TestLabelsAndTaint(t *testing.T) {
	g := NewGate(&Policy{}, t.TempDir())
	var got []string
	g.Labels().OnAdd(func(l taint.Label, src string) { got = append(got, string(l)+":"+src) })
	g.Taint(".env")
	g.Taint(".env.local") // same label again: no second callback
	g.Mark(taint.Untrusted, "example.com")
	if len(got) != 2 || got[0] != "secret:.env" || got[1] != "untrusted:example.com" {
		t.Fatalf("OnAdd fired %v", got)
	}
	if g.Tainted() != ".env" {
		t.Fatalf("Tainted = %q", g.Tainted())
	}
	labels := strings.Join(g.Labels().Labels(), ",")
	if labels != "secret,untrusted" {
		t.Fatalf("labels = %q", labels)
	}
}

// A misspelled field is a load error, not a rule that never matches.
func TestTypedVariables(t *testing.T) {
	for _, when := range []string{`effect.knd == "x"`, `session.label.exists(l, l == "x")`, `command.argv == "x"`} {
		p := &Policy{}
		if err := p.add(Rule{Name: "r", When: when, Verdict: Deny}); err == nil {
			t.Errorf("%s: loaded", when)
		}
	}
	p := &Policy{}
	for _, when := range []string{`command.argv.exists(a, a == "--force")`, `"secret" in session.labels`, `effect.target.startsWith(".git/")`} {
		if err := p.add(Rule{Name: when, When: when, Verdict: Deny}); err != nil {
			t.Errorf("%s: %v", when, err)
		}
	}
}

// A deny or ask rule that fails at run time counts as matched; an
// allow rule does not.
func TestFailClosed(t *testing.T) {
	p := &Policy{}
	for _, r := range []Rule{
		{Name: "allow-first", When: `command.argv[0] == "ls"`, Verdict: Allow},
		{Name: "ask-first", When: `command.argv[0] == "curl"`, Verdict: Ask},
	} {
		if err := p.add(r); err != nil {
			t.Fatal(err)
		}
	}
	d := p.Decide(Input{Effect: models.Effect{Kind: "net.egress"}})
	if d.Verdict != Ask || d.Rule != "ask-first" || !strings.Contains(d.Message, "failed to evaluate") {
		t.Fatalf("empty argv: %+v", d)
	}
	if d := p.Decide(Input{Argv: []string{"ls"}}); d.Verdict != Allow || d.Rule != "allow-first" {
		t.Fatalf("ls: %+v", d)
	}
}
