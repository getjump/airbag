// Package policy decides what happens to an effect: allow, deny or ask.
// Rules are CEL expressions over the effect, not over command strings,
// so `bash -c`, base64 or a different spelling of the same command do
// not slip past them.
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
	"strings"
	"time"

	"github.com/google/cel-go/cel"
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
	// Personal settings, read only from ~/.config/airbag/airbag.yaml: a
	// repository must not run commands on the host or slow sessions down.
	OnAsk   []string `yaml:"on_ask"`
	AskWait string   `yaml:"ask_wait"`
}

type Policy struct {
	Allow   []string
	Rules   []Rule
	Sources []string
	// OnAsk runs on the host for every new request, the request as JSON
	// on stdin; AskWait holds a request that long for a decision.
	OnAsk    []string
	AskWait  time.Duration
	Warnings []string
}

// MaxAskWait stays under the agents' 30-second hook timeout.
const MaxAskWait = 25 * time.Second

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

var env *cel.Env

func init() {
	var err error
	env, err = cel.NewEnv(
		cel.Variable("effect", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("command", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("session", cel.MapType(cel.StringType, cel.DynType)),
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
	personal := filepath.Join(home, ".config", "airbag", "airbag.yaml")
	for _, path := range []string{personal, filepath.Join(workspace, "airbag.yaml")} {
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
		if path != personal {
			if len(f.OnAsk) > 0 || f.AskWait != "" {
				p.Warnings = append(p.Warnings, path+": on_ask and ask_wait are ignored here; set them in "+personal)
			}
		} else {
			p.OnAsk = f.OnAsk
			if f.AskWait != "" {
				w, err := time.ParseDuration(f.AskWait)
				if err != nil {
					return nil, fmt.Errorf("%s: ask_wait: %w", path, err)
				}
				p.AskWait = min(w, MaxAskWait)
			}
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
	prg, err := env.Program(ast)
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
	vars := map[string]any{
		"effect":  map[string]string{"kind": in.Effect.Kind, "target": in.Effect.Target, "detail": in.Effect.Detail},
		"command": map[string]any{"argv": in.Argv, "line": strings.Join(in.Argv, " ")},
		"session": map[string]any{"tainted": in.Tainted, "labels": in.Labels},
	}
	best := Decision{Verdict: Allow}
	rank := map[string]int{Allow: 1, Ask: 2, Deny: 3}
	for _, r := range p.Rules {
		out, _, err := r.prg.Eval(vars)
		if err != nil {
			continue
		}
		if hit, ok := out.Value().(bool); !ok || !hit {
			continue
		}
		if best.Rule == "" || rank[r.Verdict] > rank[best.Verdict] {
			best = Decision{Verdict: r.Verdict, Rule: r.Name, Message: r.Message}
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
