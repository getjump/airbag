package policy_test

import (
	"reflect"
	"sync"
	"testing"

	"github.com/getjump/airbag/policy"
)

func TestExplicitFallbackAndImmutableConcurrentEvaluation(t *testing.T) {
	rules := []policy.Rule{
		{Name: "known", When: `effect.target == "api.example.com"`, Verdict: policy.Allow},
		{Name: "secret", When: `session.labels.exists(x, x == "secret")`, Verdict: policy.Deny},
	}
	engine, err := policy.Compile(rules, policy.Deny)
	if err != nil {
		t.Fatal(err)
	}
	rules[0].When = "true"
	if d := engine.Decide(policy.Input{Effect: policy.Effect{Target: "other.example.com"}}); d.Verdict != policy.Deny {
		t.Fatal("mutation of source rules widened compiled permissions", d)
	}
	in := policy.Input{Effect: policy.Effect{Target: "api.example.com"}, Argv: []string{"curl"}, Labels: []string{"secret"}}
	before := policy.Input{Effect: in.Effect, Argv: []string{"curl"}, Labels: []string{"secret"}}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 20 {
				if d := engine.Decide(in); d.Verdict != policy.Deny || d.Rule != "secret" {
					t.Error(d)
				}
			}
		})
	}
	wg.Wait()
	if !reflect.DeepEqual(in, before) {
		t.Fatal("evaluation changed its input")
	}
	if d := engine.Decide(policy.Input{Effect: in.Effect}); d.Verdict != policy.Allow {
		t.Fatal("explicit allow did not override the no-match fallback", d)
	}
}

func TestInvalidAndZeroEngine(t *testing.T) {
	for _, fallback := range []string{"", "ask", "invalid"} {
		if _, err := policy.Compile(nil, fallback); err == nil {
			t.Fatal("accepted fallback", fallback)
		}
	}
	if _, err := policy.Compile([]policy.Rule{{When: "effect.typo == 1", Verdict: policy.Deny}}, policy.Deny); err == nil {
		t.Fatal("invalid rules silently accepted")
	}
	var empty policy.Engine
	if d := empty.Decide(policy.Input{}); d.Verdict != policy.Deny {
		t.Fatal("zero engine granted permission", d)
	}
	var none *policy.Engine
	if d := none.Decide(policy.Input{}); d.Verdict != policy.Deny || d.Rule != policy.FallbackRule || d.Message != "policy engine not compiled" {
		t.Fatal("nil engine", d)
	}
}

// A deny fallback names itself, so the agent is told which rule held it
// back; an allow fallback names no rule.
func TestFallbackNamed(t *testing.T) {
	for fallback, rule := range map[string]string{policy.Deny: policy.FallbackRule, policy.Allow: ""} {
		engine, err := policy.Compile(nil, fallback)
		if err != nil {
			t.Fatal(err)
		}
		if d := engine.Decide(policy.Input{}); d.Verdict != fallback || d.Rule != rule {
			t.Errorf("fallback %s: %+v", fallback, d)
		}
	}
}

// effect.source tells an observed attempt (fuse, seccomp) from a
// prediction (""), so a rule on one does not match the other.
func TestEffectSource(t *testing.T) {
	engine, err := policy.Compile([]policy.Rule{
		{Name: "observed-exec", When: `effect.source == "seccomp" && effect.kind == "proc.exec"`, Verdict: policy.Deny},
	}, policy.Allow)
	if err != nil {
		t.Fatal(err)
	}
	exec := policy.Effect{Kind: "proc.exec", Target: "/usr/bin/curl"}
	if d := engine.Decide(policy.Input{Source: "seccomp", Effect: exec}); d.Verdict != policy.Deny || d.Rule != "observed-exec" {
		t.Fatalf("observed exec: %+v", d)
	}
	if d := engine.Decide(policy.Input{Effect: exec}); d.Verdict != policy.Allow {
		t.Fatalf("a prediction matched an observed-source rule: %+v", d)
	}
}
