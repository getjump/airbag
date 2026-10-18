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

// Whatever the simulate: entries say, a stub that loads serves from a
// body_file only a regular, non-secret file inside the directory of the
// file that names it: never the secret next to it, nor a file outside
// that directory, by .., an absolute path or a link.
func FuzzSimulateConfig(f *testing.F) {
	home := f.TempDir()
	cfg := filepath.Join(home, ".config", "airbag")
	for name, body := range map[string]string{
		filepath.Join(cfg, "ok.json"):        "STUB-OK",
		filepath.Join(cfg, "sub", "ok.json"): "STUB-OK",
		filepath.Join(cfg, ".env"):           "SECRET-ENV",
		filepath.Join(home, "outside.json"):  "OUTSIDE",
	} {
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			f.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			f.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, "outside.json"), filepath.Join(cfg, "link.json")); err != nil {
		f.Fatal(err)
	}
	src := filepath.Join(cfg, "airbag.yaml")
	for _, bf := range []string{"ok.json", "sub/ok.json", "./sub/../ok.json", ".env", "../../outside.json", "link.json", filepath.Join(home, "outside.json"), "~/outside.json", "sub/../../../outside.json"} {
		f.Add([]byte("simulate:\n  - match: {host: a.test, path: /x}\n    respond: {status: 200, body_file: '" + bf + "'}\n"))
	}
	f.Add([]byte("simulate:\n  - name: n\n    match: {method: GET, host: '*.a.test', query: {k: v}, headers: {X-A: '*'}}\n    respond: {headers: {Content-Type: text/plain}, body: hi, delay: 1s}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		stubs, err := decodeStubs(data)
		if err != nil {
			return
		}
		p := &Policy{}
		if err := p.addStubs(src, stubs, home, false); err != nil {
			return
		}
		if p.Simulation.Len() != len(stubs) || len(p.Stubs) != len(stubs) {
			t.Fatalf("%d stubs given, %d kept, %d compiled", len(stubs), len(p.Stubs), p.Simulation.Len())
		}
		for i, st := range p.Stubs {
			if st.Respond.BodyFile != "" {
				t.Fatalf("stub %s kept an unread body_file", st.Name)
			}
			if stubs[i].Respond.BodyFile != "" && st.Respond.Body != "STUB-OK" {
				t.Fatalf("body_file %q served %q", stubs[i].Respond.BodyFile, st.Respond.Body)
			}
		}
	})
}
