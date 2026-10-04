package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// A Pattern selects the calls of one program that wait in the outbox:
// "gh pr create" matches `gh pr create --title x` and
// `gh -R o/r pr create`. The words after the program must follow each
// other among the call's arguments that are not options. Deferring is
// a convenience, not a boundary: a call that slips past a pattern runs
// in the sandbox, without the user's credentials.
type Pattern struct {
	Program string
	Words   []string
}

var programName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// Programs airbag shims itself, or that would defer every command.
var notDeferrable = map[string]string{
	"git":    "git push already waits in the outbox; other git commands run in the branch",
	"bash":   "a shell runs anything",
	"sh":     "a shell runs anything",
	"env":    "env runs any program",
	"airbag": "airbag itself",
}

func ParsePattern(s string) (Pattern, error) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return Pattern{}, fmt.Errorf("empty")
	}
	if !programName.MatchString(f[0]) {
		return Pattern{}, fmt.Errorf("%q is not a program name (no paths: the program is looked up in PATH)", f[0])
	}
	if why := notDeferrable[f[0]]; why != "" {
		return Pattern{}, fmt.Errorf("%s cannot be deferred: %s", f[0], why)
	}
	for _, w := range f[1:] {
		if strings.HasPrefix(w, "-") {
			return Pattern{}, fmt.Errorf("%q: patterns name subcommands, not options", w)
		}
	}
	return Pattern{Program: f[0], Words: f[1:]}, nil
}

func (p Pattern) String() string { return strings.Join(append([]string{p.Program}, p.Words...), " ") }

// Match reports whether argv is a call this pattern defers. argv[0]
// must be the bare program name, as PATH lookup leaves it.
func (p Pattern) Match(argv []string) bool {
	if len(argv) == 0 || argv[0] != p.Program {
		return false
	}
	var words []string
	for i, a := range argv[1:] {
		if a == "--" {
			words = append(words, argv[i+2:]...)
			break
		}
		if !strings.HasPrefix(a, "-") {
			words = append(words, a)
		}
	}
	if len(p.Words) == 0 {
		return true
	}
	for i := 0; i+len(p.Words) <= len(words); i++ {
		if equal(words[i:i+len(p.Words)], p.Words) {
			return true
		}
	}
	return false
}

func equal(a, b []string) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return len(a) == len(b)
}

// Defers returns the pattern that defers argv, or "".
func (p *Policy) Defers(argv []string) string {
	for _, d := range p.Defer {
		if d.Match(argv) {
			return d.String()
		}
	}
	return ""
}

// DeferPrograms lists the programs that need a shim in the sandbox.
func (p *Policy) DeferPrograms() []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range p.Defer {
		if !seen[d.Program] {
			seen[d.Program] = true
			out = append(out, d.Program)
		}
	}
	return out
}
