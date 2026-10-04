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
	"reflect"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
	"gopkg.in/yaml.v3"

	"github.com/getjump/airbag/internal/models"
)

const (
	Allow = "allow"
	Deny  = "deny"
	Ask   = "ask"
)

type Rule struct {
	Name    string `yaml:"name" json:"name"`
	When    string `yaml:"when" json:"when"`
	Verdict string `yaml:"verdict" json:"verdict"`
	Message string `yaml:"message,omitempty" json:"message,omitempty"`
	Source  string `yaml:"-" json:"source"`
	prg     cel.Program
}

type File struct {
	Allow []string `yaml:"allow"`
	Rules []Rule   `yaml:"rules"`
}

type Policy struct {
	Allow   []string
	Rules   []Rule
	Sources []string
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

// The variables a rule sees. Field names come from the cel tags.
type (
	CELEffect struct {
		Kind   string `cel:"kind"`
		Target string `cel:"target"`
		Detail string `cel:"detail"`
	}
	CELCommand struct {
		Argv []string `cel:"argv"`
		Line string   `cel:"line"`
	}
	CELSession struct {
		Tainted bool     `cel:"tainted"`
		Labels  []string `cel:"labels"`
	}
)

// costLimit bounds one rule's evaluation; rules are small predicates.
const costLimit = 100_000

var env *cel.Env

func init() {
	var err error
	env, err = cel.NewEnv(
		ext.NativeTypes(reflect.TypeOf(CELEffect{}), reflect.TypeOf(CELCommand{}), reflect.TypeOf(CELSession{}),
			ext.ParseStructTags(true)),
		cel.Variable("effect", cel.ObjectType("policy.CELEffect")),
		cel.Variable("command", cel.ObjectType("policy.CELCommand")),
		cel.Variable("session", cel.ObjectType("policy.CELSession")),
	)
	if err != nil {
		panic(err)
	}
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
	for _, path := range []string{
		filepath.Join(home, ".config", "airbag", "airbag.yaml"),
		filepath.Join(workspace, "airbag.yaml"),
	} {
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
		p.Allow = append(p.Allow, f.Allow...)
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
	switch r.Verdict {
	case Allow, Deny, Ask:
	case "defer":
		r.Verdict = Ask // only git push can wait in the outbox for now
	default:
		return fmt.Errorf("verdict %q: want allow, deny or ask", r.Verdict)
	}
	ast, iss := env.Compile(r.When)
	if iss.Err() != nil {
		return iss.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return fmt.Errorf("`when` must be a boolean expression")
	}
	prg, err := env.Program(ast, cel.CostLimit(costLimit))
	if err != nil {
		return err
	}
	r.prg = prg
	p.Rules = append(p.Rules, r)
	return nil
}

// Input is one effect with its context.
type Input struct {
	Effect  models.Effect
	Argv    []string // the command that produces it, if any
	Tainted bool     // session holds the "secret" label (kept for brevity)
	Labels  []string // all session labels, for `session.labels`
}

type Decision struct {
	Verdict string `json:"verdict"`
	Rule    string `json:"rule,omitempty"`
	Message string `json:"message,omitempty"`
}

// Decide evaluates every rule; deny beats ask beats allow. No matching
// rule means allow: the sandbox and the review cover the rest.
func (p *Policy) Decide(in Input) Decision {
	argv, labels := in.Argv, in.Labels
	if argv == nil {
		argv = []string{}
	}
	if labels == nil {
		labels = []string{}
	}
	vars := map[string]any{
		"effect":  CELEffect{Kind: in.Effect.Kind, Target: in.Effect.Target, Detail: in.Effect.Detail},
		"command": CELCommand{Argv: argv, Line: strings.Join(argv, " ")},
		"session": CELSession{Tainted: in.Tainted, Labels: labels},
	}
	best := Decision{Verdict: Allow}
	rank := map[string]int{Allow: 1, Ask: 2, Deny: 3}
	for _, r := range p.Rules {
		msg := r.Message
		out, _, err := r.prg.Eval(vars)
		if err != nil {
			if r.Verdict == Allow {
				continue
			}
			msg = fmt.Sprintf("rule %q failed to evaluate (%v); treated as %s", r.Name, err, r.Verdict)
		} else if hit, ok := out.Value().(bool); !ok || !hit {
			continue
		}
		if best.Rule == "" || rank[r.Verdict] > rank[best.Verdict] {
			best = Decision{Verdict: r.Verdict, Rule: r.Name, Message: msg}
		}
	}
	return best
}

// AllowsHost reports whether a rule explicitly allows a network effect
// to a host that is not on the allowlist.
func (p *Policy) AllowsHost(host string) bool {
	d := p.Decide(Input{Effect: models.Effect{Kind: "net.connect", Target: host}})
	return d.Verdict == Allow && d.Rule != ""
}
