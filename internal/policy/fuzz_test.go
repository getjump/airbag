package policy

import (
	"strings"
	"testing"
)

// Match must stay conservative: it defers a call only when the program
// is exactly the pattern's program (a full path never matches, so it
// cannot be smuggled past the shim) and the pattern's words appear in
// order among the call's non-option arguments.
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
		// Recompute the intended answer independently.
		want := len(argv) > 0 && argv[0] == p.Program && subsequence(p.Words, nonOptions(argv[1:]))
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

func subsequence(need, have []string) bool {
	if len(need) == 0 {
		return true
	}
	for i := 0; i+len(need) <= len(have); i++ {
		ok := true
		for j := range need {
			if have[i+j] != need[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
