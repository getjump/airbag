package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/models"
)

// Match must stay conservative: it defers a call only when the program
// is exactly the pattern's program (a full path never matches, so it
// cannot be smuggled past the shim) and the pattern's words appear next
// to each other, in order, among the call's non-option arguments.
func FuzzPatternMatch(f *testing.F) {
	for _, s := range []string{"gh pr create", "npm publish", "tool run", "gh", "a b c"} {
		f.Add(s, "gh pr create --title x")
		f.Add(s, "/usr/bin/gh pr create")
	}
	f.Fuzz(func(t *testing.T, pat, line string) {
		p, err := ParsePattern(pat)
		if err != nil {
			return
		}
		if strings.ContainsAny(p.Program, "/") {
			t.Fatalf("ParsePattern kept a path in program %q", p.Program)
		}
		argv := strings.Fields(line)
		got := p.Match(argv)
		// The intended answer, by a different route: the words as a run
		// of space-separated text (neither side holds a space).
		want := len(argv) > 0 && argv[0] == p.Program && run(p.Words, nonOptions(argv[1:]))
		if got != want {
			t.Fatalf("Match(%q, %q) = %v, want %v", pat, argv, got, want)
		}
	})
}

func nonOptions(args []string) []string {
	var out []string
	for i, a := range args {
		if a == "--" {
			return append(out, args[i+1:]...)
		}
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

// run reports whether need occurs in have as adjacent words.
func run(need, have []string) bool {
	return len(need) == 0 || strings.Contains(" "+strings.Join(have, " ")+" ", " "+strings.Join(need, " ")+" ")
}

// When several rules of the same verdict match, the first one is the
// one reported, so the message the agent and the review show is stable.
func TestFirstMatchingRuleIsReported(t *testing.T) {
	ws := t.TempDir()
	_ = os.WriteFile(filepath.Join(ws, "airbag.yaml"), []byte(`
rules:
  - name: first
    when: effect.kind == "net.egress"
    verdict: deny
  - name: second
    when: effect.kind == "net.egress"
    verdict: deny
`), 0o644)
	p, err := Load(ws, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := p.Decide(Input{Effect: models.Effect{Kind: "net.egress", Target: "x"}})
	if d.Verdict != Deny || d.Rule != "first" {
		t.Fatalf("decision %+v, want deny by first", d)
	}
}
