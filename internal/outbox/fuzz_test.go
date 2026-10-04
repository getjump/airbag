package outbox

import (
	"strings"
	"testing"
)

// The invariant that matters: if GitPush accepts an argv, the canonical
// command it returns can only push. It starts with "push", carries only
// the flags on the allowlist (none of which can run a program), and its
// positionals are a remote then refspecs. A regression that let through
// --receive-pack, --exec, -o or -c would break this.
func FuzzGitPush(f *testing.F) {
	for _, s := range []string{
		"git push", "git push origin main", "git push -u origin HEAD:main",
		"git push --force-with-lease=main origin main", "git push --receive-pack=x origin main",
		"git push -o x origin", "git push --exec=/bin/sh", "git -c x=y push", "git push ''",
		"git push origin --delete feature", "git push https://h/r refs/heads/x:refs/heads/y",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		argv := strings.Fields(line)
		got, err := GitPush(argv)
		if err != nil {
			return
		}
		if len(got) == 0 || got[0] != "push" {
			t.Fatalf("accepted %q but canonical argv is %q (not a push)", argv, got)
		}
		pos := 0
		for _, a := range got[1:] {
			switch {
			case strings.HasPrefix(a, "--force-with-lease="):
				if !refspec.MatchString(strings.TrimPrefix(a, "--force-with-lease=")) {
					t.Fatalf("accepted %q: bad --force-with-lease value in %q", argv, a)
				}
			case strings.HasPrefix(a, "-"):
				if !pushFlags[a] {
					t.Fatalf("accepted %q: emitted flag %q that is not on the allowlist", argv, a)
				}
			default:
				pos++
				if pos == 1 {
					if !remoteName.MatchString(a) && !remoteURL.MatchString(a) {
						t.Fatalf("accepted %q: remote %q matches neither name nor url", argv, a)
					}
				} else if !refspec.MatchString(a) {
					t.Fatalf("accepted %q: refspec %q not allowed", argv, a)
				}
			}
		}
	})
}
