package control

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/steps"
)

// A denied tool call is answered before the step is closed: the walk of a
// large branch could hold the deny past the hook's timeout, after which
// the agent goes on as if allowed. A call that goes ahead closes it.
func TestDeniedToolCallAnswersBeforeTheStep(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	sess, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s := deferServer(t, "")
	s.Steps = steps.NewTracker(sess)
	if err := os.WriteFile(filepath.Join(sess.WSUpper(), "between.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := s.HTTPServer().Handler
	call := func(command string) string {
		t.Helper()
		body := `{"tool_name":"Bash","tool_input":{"command":"` + command + `"},"tool_use_id":"t"}`
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/hook/claude/PreToolUse", strings.NewReader(body)))
		return w.Body.String()
	}
	// A publish by full path is denied by a built-in rule.
	if out := call("/usr/bin/npm publish"); !strings.Contains(out, `"deny"`) {
		t.Fatalf("not denied: %s", out)
	}
	if sts, _ := steps.Read(sess); len(sts) != 0 {
		t.Fatalf("a denied call closed a step first: %+v", sts)
	}
	if out := call("true"); strings.Contains(out, "deny") {
		t.Fatalf("an allowed call denied: %s", out)
	}
	sts, _ := steps.Read(sess)
	if len(sts) != 1 || len(sts[0].Changes) != 1 || sts[0].Changes[0] != "+ws:between.txt" {
		t.Fatalf("the allowed call did not close the step: %+v", sts)
	}
}
