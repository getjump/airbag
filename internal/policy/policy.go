// Package policy decides what happens to an effect: allow, deny or ask.
// Rules are CEL expressions over effects. Some effects are observed (the
// proxy sees every connection, FUSE every secret read); others are
// predicted from a command line by internal/models, and a prediction
// can miss what a script does. A rule on a predicted effect is an early
// refusal and a hint for review; the boundary is the sandbox itself.
//
// Rules are type-checked when loaded: a misspelled field is an error,
// not a rule that never matches. A deny or ask rule that fails to
// evaluate counts as matched (fail closed); an allow rule that fails
// does not.
//
// Sources, merged in order: built-in rules, ~/.config/airbag/airbag.yaml,
// airbag.yaml in the workspace (read from the real workspace, so the
// agent cannot loosen its own rules). A deny anywhere wins.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/getjump/airbag/creds"
	"github.com/getjump/airbag/internal/models"
	pure "github.com/getjump/airbag/policy"
)

const (
	Allow = pure.Allow
	Deny  = pure.Deny
	Ask   = pure.Ask
)

type Rule = pure.Rule
type Input = pure.Input
type Decision = pure.Decision

type File struct {
	Allow []string `yaml:"allow"`
	// Hide: more paths to hide from the agent, relative to $HOME or
	// absolute. Hiding only takes away, so the repository may add some.
	Hide []string `yaml:"hide"`
	// Defer: commands that wait in the outbox instead of running, each
	// a program and the words that select its calls ("gh pr create").
	Defer []string `yaml:"defer"`
	// Credentials: tokens the agent uses without holding them. Only the
	// user's own file may name them, never a repository's.
	Credentials []creds.Binding `yaml:"credentials"`
	Rules       []Rule          `yaml:"rules"`
}

type Policy struct {
	engine      *pure.Engine
	Allow       []string
	Hide        []string
	Defer       []Pattern
	Credentials []creds.Binding
	Rules       []Rule
	Sources     []string
}

// Builtin: effects that cannot be undone and cannot wait in the outbox.
var Builtin = []Rule{
	{
		Name:    "secret-taint",
		When:    `session.tainted && effect.kind == "net.egress"`,
		Verdict: Deny,
		Message: "this session read a secret (.env); data can no longer leave the machine",
	},
	{
		Name:    "no-publish",
		When:    `effect.kind == "net.egress" && effect.detail == "publish"`,
		Verdict: Deny,
		Message: "publishing a package cannot be undone; publish from the host after review",
	},
}

// Load reads the policy sources that exist.
func Load(workspace, home string) (*Policy, error) {
	p := &Policy{Sources: []string{"built-in"}}
	for _, r := range Builtin {
		r.Source = "built-in"
		if err := p.add(r); err != nil {
			return nil, err
		}
	}
	userFile := filepath.Join(home, ".config", "airbag", "airbag.yaml")
	for _, path := range []string{userFile, filepath.Join(workspace, "airbag.yaml")} {
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		var f File
		if err := yaml.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		p.Sources = append(p.Sources, path)
		if len(f.Credentials) > 0 && path != userFile {
			return nil, fmt.Errorf("%s: credentials can only be set in %s: a repository must not decide which hosts get your tokens", path, userFile)
		}
		for _, b := range f.Credentials {
			if err := b.Validate(); err != nil {
				return nil, fmt.Errorf("%s: credentials: %w", path, err)
			}
			for _, o := range p.Credentials {
				if o.Name == b.Name {
					return nil, fmt.Errorf("%s: credentials: %s twice", path, b.Name)
				}
			}
			p.Credentials = append(p.Credentials, b)
		}
		p.Allow = append(p.Allow, f.Allow...)
		p.Hide = append(p.Hide, f.Hide...)
		for _, d := range f.Defer {
			pat, err := ParsePattern(d)
			if err != nil {
				return nil, fmt.Errorf("%s: defer %q: %w", path, d, err)
			}
			p.Defer = append(p.Defer, pat)
		}
		for i, r := range f.Rules {
			if r.Name == "" {
				r.Name = fmt.Sprintf("%s#%d", filepath.Base(path), i+1)
			}
			r.Source = path
			if err := p.add(r); err != nil {
				return nil, fmt.Errorf("%s: rule %s: %w", path, r.Name, err)
			}
		}
	}
	return p, nil
}

func (p *Policy) add(r Rule) error {
	rules := append(append([]Rule(nil), p.Rules...), r)
	engine, err := pure.Compile(rules, Allow)
	if err != nil {
		return err
	}
	if r.Verdict == "defer" {
		r.Verdict = Ask
	}
	p.Rules = append(p.Rules, r)
	p.engine = engine
	return nil
}

// Decide preserves Airbag's native allow fallback. The public engine requires
// embedders to choose their own fallback explicitly.
func (p *Policy) Decide(in Input) Decision {
	engine := p.engine
	if engine == nil {
		var err error
		engine, err = pure.Compile(p.Rules, Allow)
		if err != nil {
			return Decision{Verdict: Deny, Message: err.Error()}
		}
	}
	return engine.Decide(in)
}

// AllowsHost reports whether a rule explicitly allows a network effect
// to a host that is not on the allowlist.
func (p *Policy) AllowsHost(host string) bool {
	d := p.Decide(Input{Effect: models.Effect{Kind: "net.connect", Target: host}})
	return d.Verdict == Allow && d.Rule != ""
}
