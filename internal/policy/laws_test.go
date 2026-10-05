package policy

import (
	"reflect"
	"testing"
	"testing/quick"

	"github.com/getjump/airbag/internal/models"
)

// Replay uses the pure Decide function on recorded inputs, not live Gate state.
// A matching extra deny cannot increase authority, regardless of other rules.
func TestDenyMonotonicAndDecisionReplay(t *testing.T) {
	p := &Policy{}
	for _, r := range []Rule{{Name: "allow", When: "true", Verdict: Allow}, {Name: "ask", When: `effect.kind == "fs.write"`, Verdict: Ask}} {
		if err := p.add(r); err != nil {
			t.Fatal(err)
		}
	}
	strict := &Policy{Rules: append([]Rule(nil), p.Rules...)}
	if err := strict.add(Rule{Name: "deny", When: "true", Verdict: Deny}); err != nil {
		t.Fatal(err)
	}
	if err := quick.Check(func(write, secret bool, target string) bool {
		kind := "fs.read"
		if write {
			kind = "fs.write"
		}
		in := Input{Effect: models.Effect{Kind: kind, Target: target}, Tainted: secret, Labels: []string{"untrusted"}, Argv: []string{"tool", target}}
		before := Input{Effect: in.Effect, Tainted: in.Tainted, Labels: append([]string(nil), in.Labels...), Argv: append([]string(nil), in.Argv...)}
		first, replay := p.Decide(in), p.Decide(in)
		return first == replay && strict.Decide(in).Verdict == Deny && reflect.DeepEqual(in, before)
	}, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
