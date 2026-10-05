package outbox

import (
	"strings"
	"testing"
)

// The flags an intent may carry, written out here rather than read from
// pushFlags: a flag added there must be added here too, on purpose.
var wantFlags = map[string]bool{
	"-f": true, "--force": true, "--force-with-lease": true, "--force-if-includes": true,
	"-u": true, "--set-upstream": true, "--tags": true, "--follow-tags": true,
	"-d": true, "--delete": true, "--atomic": true, "-q": true, "--quiet": true,
	"-v": true, "--verbose": true, "--no-verify": true,
}

// Options of git or git push that run a program or change where git
// looks; none may ever reach the host.
var neverFlags = []string{"--receive-pack", "--exec", "-o", "--push-option", "--upload-pack", "-c", "--repo", "--git-dir", "--work-tree", "--config-env"}

// The invariant that matters: if GitPush accepts an argv, the canonical
// command it returns can only push. It starts with "push", carries only
// the flags listed above (none of which can run a program), and its
// positionals are a remote then refspecs, none starting with "-" and no
// URL whose host does. The checks are written out here, not taken from
// gitpush.go, so a regression there that let through --receive-pack,
// --exec, -o or -c breaks this.
func FuzzGitPush(f *testing.F) {
	for _, s := range []string{
		"git push", "git push origin main", "git push -u origin HEAD:main",
		"git push --force-with-lease=main origin main", "git push --receive-pack=x origin main",
		"git push -o x origin", "git push --exec=/bin/sh", "git -c x=y push", "git push ''",
		"git push origin --delete feature", "git push https://h/r refs/heads/x:refs/heads/y",
		"git push ssh://-oProxyCommand=x/r main", "git push git@-oProxyCommand=x:r main",
		"git push --upload-pack=x origin", "git push --repo=x",
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
			for _, n := range neverFlags {
				if a == n || strings.HasPrefix(a, n+"=") || (len(n) == 2 && strings.HasPrefix(a, n)) {
					t.Fatalf("accepted %q: emitted %q", argv, a)
				}
			}
			switch {
			case strings.HasPrefix(a, "--force-with-lease="):
				if v := strings.TrimPrefix(a, "--force-with-lease="); v == "" || strings.HasPrefix(v, "-") || strings.ContainsAny(v, " \t\n\\") {
					t.Fatalf("accepted %q: bad --force-with-lease value in %q", argv, a)
				}
			case strings.HasPrefix(a, "-"):
				if !wantFlags[a] {
					t.Fatalf("accepted %q: emitted flag %q that is not on the list", argv, a)
				}
			default:
				pos++
				if pos == 1 && urlHostDash(a) {
					t.Fatalf("accepted %q: remote %q has a host starting with -", argv, a)
				}
			}
		}
	})
}

// urlHostDash: a URL remote whose host starts with "-", which ssh would
// read as an option.
func urlHostDash(r string) bool {
	rest, ok := strings.CutPrefix(r, "ssh://")
	if !ok {
		rest, ok = strings.CutPrefix(r, "https://")
	}
	if ok {
		auth, _, _ := strings.Cut(rest, "/")
		if i := strings.LastIndex(auth, "@"); i >= 0 {
			auth = auth[i+1:]
		}
		return strings.HasPrefix(auth, "-")
	}
	if rest, ok := strings.CutPrefix(r, "git@"); ok {
		return strings.HasPrefix(rest, "-")
	}
	return false
}
