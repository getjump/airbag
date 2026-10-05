package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	s := deferServer(t, "defer: [gh pr create]\n")
	notes := filepath.Join(s.Root, "docs", "notes.md")
	d := ask(t, s, outbox.Intent{Argv: []string{"gh", "pr", "create", "--body-file", notes}, Cwd: s.Root,
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

// An intent's body is read up to maxBody: one larger is refused, not
// held in the host's memory.
func TestIntentBodyBounded(t *testing.T) {
	s := deferServer(t, "")
	big := `{"kind":"` + outbox.KindPush + `","argv":["git","push","origin","` + strings.Repeat("a", maxBody) + `"]}`
	w := httptest.NewRecorder()
	s.intent(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/intent", strings.NewReader(big)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d", w.Code)
	}
}

// A secret read is answered only once its entry is in the log, which a
// resumed session reads the label back from.
func TestTaintFailsWhenNotLogged(t *testing.T) {
	s := deferServer(t, "")
	_ = s.Log.Close()
	w := httptest.NewRecorder()
	s.taint(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/taint", strings.NewReader(`{"file":".env","exe":"/bin/cat"}`)))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status %d", w.Code)
	}
}

// Past MaxConns connections open, one more is closed at once.
func TestControlSocketCapped(t *testing.T) {
	s := deferServer(t, "")
	sock := filepath.Join(t.TempDir(), "ctl.sock")
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = s.Serve(l); close(done) }()
	defer func() { l.Close(); <-done }()
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	dial := func() net.Conn {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		return c
	}
	for range MaxConns {
		dial()
	}
	// The server has accepted them once a request on the last is answered.
	last := dial()
	_ = last.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = last.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("connection past the cap: %v", err)
	}
}
