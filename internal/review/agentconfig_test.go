package review

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

// cfgSession makes a session with a branched $HOME and returns it with
// the real and branch paths of ~/.claude.json.
func cfgSession(t *testing.T) (s *session.Session, realPath, branchPath string) {
	t.Helper()
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	realPath = filepath.Join(home, ".claude.json")
	branchPath = filepath.Join(s.HomeUpper(), ".claude.json")
	return s, realPath, branchPath
}

func writeCfg(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readCfg(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse %s: %v (%s)", path, err, b)
	}
	return m
}

func TestWriteBackAllowlistedOnly(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1,"userID":"u"}`)
	writeCfg(t, branchPath, `{"numStartups":2,"userID":"u"}`)

	msgs := WriteBackConfigs(s)
	if len(msgs) != 1 {
		t.Fatalf("messages = %v, want one", msgs)
	}
	if got := readCfg(t, realPath)["numStartups"]; got != float64(2) {
		t.Errorf("real numStartups = %v, want 2", got)
	}
	// Only benign keys differed, so the branch copy is dropped and review
	// shows nothing for the file.
	if _, err := os.Stat(branchPath); !os.IsNotExist(err) {
		t.Errorf("branch copy not dropped: err=%v", err)
	}
}

func TestWriteBackMixedChangeKeepsSensitiveInBranch(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1}`)
	writeCfg(t, branchPath, `{"numStartups":2,"mcpServers":{"x":{"command":"evil"}}}`)

	WriteBackConfigs(s)

	real := readCfg(t, realPath)
	if real["numStartups"] != float64(2) {
		t.Errorf("benign key not written back: %v", real["numStartups"])
	}
	if _, ok := real["mcpServers"]; ok {
		t.Error("mcpServers reached the real file")
	}
	if _, err := os.Stat(branchPath); err != nil {
		t.Errorf("branch copy dropped although a non-benign key changed: %v", err)
	}
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
	keys, persist, ok := configKeyChange(c)
	if !ok || !persist || !slices.Contains(keys, "mcpServers") {
		t.Errorf("review of config: keys=%v persist=%v ok=%v, want mcpServers persist", keys, persist, ok)
	}
	if slices.Contains(keys, "numStartups") {
		t.Error("a written-back key still shows as changed in review")
	}
}

func TestWriteBackKeepsConcurrentHostEdit(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	// The branch was taken from a real file with theme "dark"; while the
	// session ran, the host changed theme to "light". Write-back must set
	// the benign counter without reverting the host's theme.
	writeCfg(t, branchPath, `{"numStartups":2,"theme":"dark"}`)
	writeCfg(t, realPath, `{"numStartups":1,"theme":"light"}`)

	WriteBackConfigs(s)

	real := readCfg(t, realPath)
	if real["theme"] != "light" {
		t.Errorf("host edit clobbered: theme = %v, want light", real["theme"])
	}
	if real["numStartups"] != float64(2) {
		t.Errorf("benign key not written back: %v", real["numStartups"])
	}
}

func TestWriteBackMalformedBranchLeavesRealAlone(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1}`)
	writeCfg(t, branchPath, `{not valid json`)

	WriteBackConfigs(s)

	if got := readCfg(t, realPath)["numStartups"]; got != float64(1) {
		t.Errorf("real file changed despite malformed branch: %v", got)
	}
	if _, err := os.Stat(branchPath); err != nil {
		t.Errorf("malformed branch copy removed: %v", err)
	}
}

func TestWriteBackMalformedRealNeverCorrupts(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{corrupt`)
	writeCfg(t, branchPath, `{"numStartups":2}`)

	WriteBackConfigs(s)

	b, err := os.ReadFile(realPath)
	if err != nil || string(b) != `{corrupt` {
		t.Errorf("real file was modified: %q (%v)", b, err)
	}
}

func TestWriteBackNoHomeBranch(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home, OverHome: false})
	if err != nil {
		t.Fatal(err)
	}
	writeCfg(t, filepath.Join(s.HomeUpper(), ".claude.json"), `{"numStartups":2}`)
	if msgs := WriteBackConfigs(s); msgs != nil {
		t.Errorf("wrote back without a $HOME branch: %v", msgs)
	}
}

func TestAgentMemory(t *testing.T) {
	for rel, want := range map[string]bool{
		".claude/projects/-home-me-proj/memory/NOTES.md": true,
		".claude/projects/-home-me-proj/memory":          true,
		".claude/projects/-home-me-proj/sess.jsonl":      false,
		".claude/projects/memory/x":                      false,
		".claude/memory/x":                               false,
	} {
		if got := agentMemory(rel); got != want {
			t.Errorf("agentMemory(%q) = %v, want %v", rel, got, want)
		}
	}
}
