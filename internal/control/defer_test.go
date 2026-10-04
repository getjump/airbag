package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/models"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/policy"
)

func deferServer(t *testing.T, yaml string) *Server {
	t.Helper()
	ws, home, dir := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "airbag.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(ws, home)
	if err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "effects.db")
	log, err := effects.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	box, err := outbox.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close(); _ = box.Close() })
	return &Server{Box: box, Log: log, Gate: policy.NewGate(pol, dir), Root: ws}
}

func ask(t *testing.T, s *Server, in outbox.Intent) DeferReply {
	t.Helper()
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.deferCmd(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/defer", bytes.NewReader(body)))
	var d DeferReply
	if err := json.NewDecoder(w.Body).Decode(&d); err != nil {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	return d
}

func TestDeferQueues(t *testing.T) {
	s := deferServer(t, "defer: [pubtool release]\n")
	notes := filepath.Join(s.Root, "docs", "notes.md")
	d := ask(t, s, outbox.Intent{Argv: []string{"pubtool", "release", "--body-file", notes}, Cwd: s.Root,
		Files: map[string]string{notes: "abc"}})
	if d.Queued == nil || d.Queued.Kind != outbox.KindCmd || d.Queued.Files["docs/notes.md"] != "abc" {
		t.Fatalf("not queued: %+v", d)
	}
	if d := ask(t, s, outbox.Intent{Argv: []string{"gh", "pr", "list"}, Cwd: s.Root}); !d.Run {
		t.Fatalf("a call no entry matches did not run: %+v", d)
	}
}

func TestDeferRefuses(t *testing.T) {
	s := deferServer(t, `
defer: [gh pr create]
rules:
  - name: no-pr-after-web
    when: '"untrusted" in session.labels && effect.kind == "intent.cmd"'
    verdict: deny
`)
	outside := filepath.Join(t.TempDir(), "body.md")
	if d := ask(t, s, outbox.Intent{Argv: []string{"gh", "pr", "create", "-F", outside}, Cwd: s.Root,
		Files: map[string]string{outside: "abc"}}); !strings.Contains(d.Refused, "outside the workspace") {
		t.Fatalf("a file outside the workspace was queued: %+v", d)
	}
	if d := ask(t, s, outbox.Intent{Argv: []string{"gh", "pr", "create"}, Cwd: "/elsewhere"}); d.Refused == "" {
		t.Fatalf("queued from outside the workspace: %+v", d)
	}
	if d := ask(t, s, outbox.Intent{Argv: []string{"gh", "pr", "create", "--body-file=config/.env.local"}, Cwd: s.Root}); !strings.Contains(d.Refused, "secret file") {
		t.Fatalf("a call naming a secret file was queued: %+v", d)
	}
	s.Gate.Mark("untrusted", "web")
	if d := ask(t, s, outbox.Intent{Argv: []string{"gh", "pr", "create"}, Cwd: s.Root}); !strings.Contains(d.Refused, "no-pr-after-web") {
		t.Fatalf("the rule did not apply: %+v", d)
	}
}

// A deferred call does not happen in the sandbox, so what a model
// predicts for it (here a publish, which a built-in rule denies) is
// replaced by the intent.
func TestJudgeDeferred(t *testing.T) {
	s := deferServer(t, "defer: [npm publish]\n")
	if d, _ := s.judge(models.Command{Argv: []string{"npm", "publish"}, Effects: []models.Effect{{Kind: models.NetEgress, Detail: "publish"}}}); d.Verdict != policy.Allow {
		t.Fatalf("deferred publish refused: %+v", d)
	}
	if d, _ := s.judge(models.Command{Argv: []string{"/usr/bin/npm", "publish"}, Effects: []models.Effect{{Kind: models.NetEgress, Detail: "publish"}}}); d.Verdict != policy.Deny {
		t.Fatalf("a publish by full path is not deferred, so it is denied: %+v", d)
	}
}
