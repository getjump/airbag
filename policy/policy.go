// Package policy compiles and evaluates CEL rules over explicit effect snapshots.
// It does not load files, resolve credentials, persist approvals or enforce effects.
package policy

import (
	"fmt"
	"reflect"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
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
}

// Effect is a policy projection, not evidence that an operation succeeded.
type Effect struct {
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func (e Effect) String() string {
	s := e.Kind
	if e.Target != "" {
		s += " " + e.Target
	}
	if e.Detail != "" {
		s += " (" + e.Detail + ")"
	}
	return s
}

type compiledRule struct {
	Rule
	prg cel.Program
}

// Engine owns compiled rules. Callers may share it for concurrent evaluations.
type Engine struct {
	rules    []compiledRule
	fallback string
}

// Compile copies rules and requires an explicit allow/deny fallback. Airbag's
// native workflow supplies Allow; embedders can choose Deny. Compilation errors
// prevent creation of an engine rather than dropping a rule.
func Compile(rules []Rule, fallback string) (*Engine, error) {
	if fallback != Allow && fallback != Deny {
		return nil, fmt.Errorf("fallback must be allow or deny")
	}
	p := &Engine{fallback: fallback}
	for _, r := range rules {
		compiled, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.Name, err)
		}
		p.rules = append(p.rules, compiled)
	}
	return p, nil
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

func compileRule(r Rule) (compiledRule, error) {
	switch r.Verdict {
	case Allow, Deny, Ask:
	case "defer":
		// What waits is chosen by `defer:` entries, which put a shim in
		// front of the program; a rule cannot reach a call without one.
		r.Verdict = Ask
	default:
		return compiledRule{}, fmt.Errorf("verdict %q: want allow, deny or ask", r.Verdict)
	}
	ast, iss := env.Compile(r.When)
	if iss.Err() != nil {
		return compiledRule{}, iss.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return compiledRule{}, fmt.Errorf("`when` must be a boolean expression")
	}
	prg, err := env.Program(ast, cel.CostLimit(costLimit))
	if err != nil {
		return compiledRule{}, err
	}
	return compiledRule{Rule: r, prg: prg}, nil
}

// Input is one effect with its context.
type Input struct {
	Effect  Effect
	Argv    []string // the command that produces it, if any
	Tainted bool     // session holds the "secret" label (kept for brevity)
	Labels  []string // all session labels, for `session.labels`
}

type Decision struct {
	Verdict string `json:"verdict"`
	Rule    string `json:"rule,omitempty"`
	Message string `json:"message,omitempty"`
}

// FallbackRule names the decision of an engine that denies: when no rule
// matched and its fallback is deny, or when it was never compiled. An
// allow fallback names no rule.
const FallbackRule = "fallback"

// Decide evaluates a snapshot without I/O. Deny beats ask beats allow;
// no matching rule returns the fallback supplied to Compile. A nil
// engine, or one not made by Compile, denies.
func (p *Engine) Decide(in Input) Decision {
	if p == nil || p.fallback == "" {
		return Decision{Verdict: Deny, Rule: FallbackRule, Message: "policy engine not compiled"}
	}
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
	best := Decision{Verdict: p.fallback}
	if best.Verdict == Deny {
		best.Rule, best.Message = FallbackRule, "no rule matched, and this policy denies what none allows"
	}
	matched := false
	rank := map[string]int{Allow: 1, Ask: 2, Deny: 3}
	for _, r := range p.rules {
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
		if !matched || rank[r.Verdict] > rank[best.Verdict] {
			best = Decision{Verdict: r.Verdict, Rule: r.Name, Message: msg}
			matched = true
		}
	}
	return best
}

// Explain is the text an agent sees when it is blocked.
func Explain(d Decision, askID string) string {
	msg := fmt.Sprintf("airbag: blocked by policy %q", d.Rule)
	if d.Message != "" {
		msg += ": " + d.Message
	}
	if d.Verdict == Ask {
		msg += fmt.Sprintf(". This needs the user's approval: ask them to run `airbag approve %s`, then retry.", askID)
	}
	return msg
}
