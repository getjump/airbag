// Package taint is airbag's label layer. A session carries a set of
// labels, each put there by some event with a source: reading a secret
// file labels the session "secret"; pulling content from a web host
// labels it "untrusted". Policy rules read the labels (CEL
// `session.labels`), so a rule can say an irreversible effect must not
// run once the session holds a given label — the information-flow idea
// that data of a kind must not reach an effect of a kind.
//
// This is deliberately coarse: the label is on the whole session, not
// on individual values. Per-value flow (which byte went where) is a
// later step; the label set is the shared substrate it will build on,
// and what the proxy, the mirror and the review already read today.
package taint

import (
	"sort"
	"sync"
)

// Label names a kind of data or trust the session has taken on.
type Label string

const (
	// Secret: the session read a secret file. Egress is then refused
	// except to model APIs, and the mirror serves only its cache.
	Secret Label = "secret"
	// Untrusted: the session pulled in content from outside (a web
	// page, an issue, tool output). A rule may keep untrusted input
	// from driving an irreversible effect.
	Untrusted Label = "untrusted"
)

// Set is the session's labels, each with the source that added it.
type Set struct {
	mu      sync.Mutex
	sources map[Label][]string
	onAdd   []func(Label, string)
	// hooked[l] is closed once the hooks for l's first Add have run.
	hooked map[Label]chan struct{}
}

func NewSet() *Set { return &Set{sources: map[Label][]string{}, hooked: map[Label]chan struct{}{}} }

// OnAdd registers f to run the first time a label is added, before Add
// returns, so an observer (close tunnels, log) acts before the action
// that triggered the label proceeds. A later Add of the label returns
// only once they have run too: the action that triggered it may be a
// retry of one whose wait for the hooks gave up.
func (s *Set) OnAdd(f func(Label, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onAdd = append(s.onAdd, f)
}

// Add records that source gave the session label. It returns true the
// first time that label appears; the hooks run only then. Every Add
// returns after they have.
func (s *Set) Add(label Label, source string) bool {
	s.mu.Lock()
	_, had := s.sources[label]
	s.sources[label] = append(s.sources[label], source)
	hooks := s.onAdd
	done, ok := s.hooked[label]
	if !ok {
		done = make(chan struct{})
		s.hooked[label] = done
	}
	s.mu.Unlock()
	if had {
		<-done
		return false
	}
	defer close(done)
	for _, f := range hooks {
		f(label, source)
	}
	return true
}

// Has reports whether the session carries label.
func (s *Set) Has(label Label) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sources[label]
	return ok
}

// Source returns the first source that added label, or "".
func (s *Set) Source(label Label) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v := s.sources[label]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Sources returns every source that added label, in order, deduped.
func (s *Set) Sources(label Label) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, v := range s.sources[label] {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// Labels returns the set's labels as sorted strings, for CEL.
func (s *Set) Labels() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.sources))
	for l := range s.sources {
		out = append(out, string(l))
	}
	sort.Strings(out)
	return out
}
