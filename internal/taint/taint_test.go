package taint

import (
	"strings"
	"testing"
)

func TestSet(t *testing.T) {
	s := NewSet()
	var fired []string
	s.OnAdd(func(l Label, src string) { fired = append(fired, string(l)+":"+src) })

	if !s.Add(Secret, ".env") {
		t.Fatal("first Add should report new")
	}
	if s.Add(Secret, "apps/web/.env") {
		t.Fatal("second Add of same label should report not new")
	}
	if !s.Add(Untrusted, "example.com") {
		t.Fatal("new label should report new")
	}
	// The hook runs only on the first appearance of a label.
	if strings.Join(fired, ",") != "secret:.env,untrusted:example.com" {
		t.Fatalf("hooks fired %v", fired)
	}
	if !s.Has(Secret) || !s.Has(Untrusted) {
		t.Fatal("Has")
	}
	if s.Source(Secret) != ".env" {
		t.Fatalf("Source = %q, want first", s.Source(Secret))
	}
	if got := strings.Join(s.Sources(Secret), ","); got != ".env,apps/web/.env" {
		t.Fatalf("Sources = %q", got)
	}
	if got := strings.Join(s.Labels(), ","); got != "secret,untrusted" {
		t.Fatalf("Labels = %q", got)
	}
}
