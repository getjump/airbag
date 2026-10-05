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
}
