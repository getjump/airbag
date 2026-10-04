package secrets

import (
	"fmt"
	"io"
	"strings"

	"github.com/getjump/airbag/internal/creds"
	"github.com/getjump/airbag/internal/policy"
)

// ForSession is the registry a session starts with, built on the host
// before the agent runs: the workspace's secret files, the credentials
// whose values setupCredentials read, and the `secrets:` entries of the
// user's configuration, read now. An entry that cannot be read is left
// out with a warning to w.
func ForSession(ws, home string, pol *policy.Policy, live creds.Set, w io.Writer) *Registry {
	r := New(FromFiles(ws)...)
	for _, l := range live {
		r.Add(Marked("credential "+l.Name, l.Value)...)
	}
	if pol == nil {
		return r
	}
	for _, e := range pol.Secrets {
		v, err := creds.Read(e.Source, home)
		if err != nil {
			fmt.Fprintf(w, "airbag: secret %s not registered (%v)\n", e.Name, err)
			continue
		}
		if len(v) < MinMarked {
			fmt.Fprintf(w, "airbag: secret %s not registered: shorter than %d characters\n", e.Name, MinMarked)
			continue
		}
		r.Add(Marked("secret "+e.Name, v)...)
	}
	return r
}

// Load is the registry as review and apply rebuild it after a session:
// the workspace's secret files as they are now, and the credentials and
// `secrets:` entries of the user's configuration. Sources that run a
// command are left out: they ran when the session started, and looking
// at a review should not run them again.
func Load(ws, home string) *Registry {
	r := New(FromFiles(ws)...)
	pol, err := policy.Load(ws, home)
	if err != nil {
		return r
	}
	for _, b := range pol.Credentials {
		if v, err := read(b.Source, home); err == nil {
			r.Add(Marked("credential "+b.Name, v)...)
		}
	}
	for _, e := range pol.Secrets {
		if v, err := read(e.Source, home); err == nil {
			r.Add(Marked("secret "+e.Name, v)...)
		}
	}
	return r
}

func read(source, home string) (string, error) {
	if strings.HasPrefix(source, "command:") {
		return "", fmt.Errorf("not run again")
	}
	return creds.Read(source, home)
}
