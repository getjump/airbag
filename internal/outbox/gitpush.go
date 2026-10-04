package outbox

import (
	"fmt"
	"regexp"
	"strings"
)

// Intents run on the host with the user's credentials, and their argv
// comes from the agent. So an intent is never an arbitrary command: it
// is parsed into a narrow shape and rebuilt by airbag.

var (
	remoteName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	remoteURL  = regexp.MustCompile(`^(https://|ssh://|git@[A-Za-z0-9][A-Za-z0-9.-]*:)[^\s]+$`)
	refspec    = regexp.MustCompile(`^\+?[A-Za-z0-9._/@{}^~:-]+$`)
)

// pushFlags are the only options accepted; anything that can run a
// program (--receive-pack, --exec, -c, -o) is rejected.
var pushFlags = map[string]bool{
	"-f": true, "--force": true, "--force-with-lease": true, "--force-if-includes": true,
	"-u": true, "--set-upstream": true, "--tags": true, "--follow-tags": true,
	"-d": true, "--delete": true, "--atomic": true, "-q": true, "--quiet": true,
	"-v": true, "--verbose": true, "--no-verify": true,
}

// GitPush validates `git push ...` and returns the canonical argv
// (without "git"): flags, then remote, then refspecs.
func GitPush(argv []string) ([]string, error) {
	if len(argv) < 2 || argv[0] != "git" || argv[1] != "push" {
		return nil, fmt.Errorf("only `git push ...` intents are supported")
	}
	var flags, pos []string
	for _, a := range argv[2:] {
		switch {
		case a == "--":
			continue
		case strings.HasPrefix(a, "--force-with-lease="):
			if !refspec.MatchString(strings.TrimPrefix(a, "--force-with-lease=")) {
				return nil, fmt.Errorf("unsupported value in %q", a)
			}
			flags = append(flags, a)
		case strings.HasPrefix(a, "-"):
			if !pushFlags[a] {
				return nil, fmt.Errorf("git push option %q is not allowed in an intent", a)
			}
			flags = append(flags, a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) > 0 {
		if r := pos[0]; !remoteName.MatchString(r) && !remoteURL.MatchString(r) {
			return nil, fmt.Errorf("remote %q is not a remote name or an https/ssh URL", r)
		}
		if r := pos[0]; dashHost(r) {
			return nil, fmt.Errorf("remote %q: a host starting with - would be an option to ssh", r)
		}
		for _, r := range pos[1:] {
			if !refspec.MatchString(r) {
				return nil, fmt.Errorf("refspec %q is not allowed", r)
			}
		}
	}
	return append(append([]string{"push"}, flags...), pos...), nil
}

// dashHost reports whether an ssh:// or https:// remote names a host
// starting with "-" (ssh://-oProxyCommand=...). git refuses those too,
// since 2.14.1; the intent runs on the host, so airbag does not rely on it.
func dashHost(r string) bool {
	rest, ok := strings.CutPrefix(r, "ssh://")
	if !ok {
		if rest, ok = strings.CutPrefix(r, "https://"); !ok {
			return false
		}
	}
	auth, _, _ := strings.Cut(rest, "/")
	if i := strings.LastIndex(auth, "@"); i >= 0 {
		auth = auth[i+1:]
	}
	return strings.HasPrefix(auth, "-")
}
