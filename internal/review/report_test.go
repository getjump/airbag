package review

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/steps"
)

func TestReportJSONContainsReviewDataWithoutInternalPaths(t *testing.T) {
	s := &session.Session{Meta: session.Meta{
		ID: "s-1", Argv: []string{"agent", "--safe"}, Status: session.StatusStopped,
		ExitCode: 2, Workspace: "/work/project", Created: time.Unix(10, 0), Ended: time.Unix(12, 0),
	}}
	changes := []Change{{
		Layer: "ws", Rel: "src/main.go", Path: "/work/project/src/main.go",
		Upper: "/tmp/airbag/upper/src/main.go", Kind: Modified, Flags: []string{"persist"},
	}}
	events := []effects.Effect{
		{Kind: "secret.read", Target: "/work/project/.env", Reason: "cat"},
		{Kind: "label", Target: "example.test", Verdict: "untrusted"},
		{Kind: "net.egress", Target: "api.example.test:443"},
		{Kind: "net.egress", Target: "blocked.example.test:443", Verdict: "deny"},
		{Kind: "net.egress", Target: "cut.example.test:443", Verdict: "cut"},
		{Kind: "pkg.fetch", Target: "example.test/package"},
		{Kind: "command", Target: "git push origin main", Verdict: "deny", Reason: "no-push"},
	}
	intents := []outbox.Intent{{ID: "i-1", Argv: []string{"git", "push"}, Cwd: "/work/project", Status: outbox.Pending}}
	toolSteps := []steps.Step{{N: 1, Tool: "bash", Summary: "updated source", Changes: []string{"~ws:src/main.go"}}}

	report := Collect(s, changes, events, intents, toolSteps)
	var encoded bytes.Buffer
	if err := WriteJSON(&encoded, report); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["session"].(map[string]any)["duration"] != "2s" {
		t.Fatalf("session duration = %v", got["session"])
	}
	change := got["changes"].([]any)[0].(map[string]any)
	if change["path"] != "src/main.go" || change["layer"] != "ws" || change["kind"] != Modified {
		t.Fatalf("change = %v", change)
	}
	if _, ok := change["Upper"]; ok {
		t.Fatalf("internal upper path leaked: %v", change)
	}
	if change["flags"].([]any)[0] != "persist" {
		t.Fatalf("change flags = %v", change["flags"])
	}
	labels := got["labels"].([]any)[0].(map[string]any)
	if labels["label"] != "untrusted" || labels["source"] != "example.test" {
		t.Fatalf("label source = %v", labels)
	}
	if got["packages"].([]any)[0] != "example.test/package" {
		t.Fatalf("packages = %v", got["packages"])
	}
	step := got["steps"].([]any)[0].(map[string]any)
	if step["tool"] != "bash" || step["summary"] != "updated source" || len(step["changes"].([]any)) != 1 {
		t.Fatalf("tool step = %v", step)
	}
	secret := got["secrets_read"].([]any)[0].(map[string]any)
	if secret["file"] != "/work/project/.env" || secret["program"] != "cat" {
		t.Fatalf("secret read = %v", secret)
	}
	network := got["network"].(map[string]any)
	if network["allowed"].(map[string]any)["count"] != float64(1) ||
		network["denied"].(map[string]any)["count"] != float64(1) ||
		network["cut"].(map[string]any)["count"] != float64(1) {
		t.Fatalf("network summary = %v", network)
	}
	blocked := got["blocked_effects"].([]any)[0].(map[string]any)
	if blocked["verdict"] != "deny" || blocked["rule"] != "no-push" {
		t.Fatalf("blocked effect = %v", blocked)
	}
	intent := got["outbox"].([]any)[0].(map[string]any)
	if intent["id"] != "i-1" || intent["status"] != outbox.Pending || len(intent["argv"].([]any)) != 2 {
		t.Fatalf("outbox intent = %v", intent)
	}
	if _, ok := intent["cwd"]; ok {
		t.Fatalf("outbox leaked unrequested cwd: %v", intent)
	}
}

func TestRenderUsesCollectedReviewFields(t *testing.T) {
	s := &session.Session{Meta: session.Meta{ID: "s-2", Workspace: "/work", Status: session.StatusStopped}}
	events := []effects.Effect{{Kind: "net.egress", Target: "api.example.test:443"}}
	var text bytes.Buffer
	Render(&text, s, nil, events, nil, nil)
	if !strings.Contains(text.String(), "Network") || !strings.Contains(text.String(), "api.example.test") {
		t.Fatalf("human review lost collected network data:\n%s", text.String())
	}
}
