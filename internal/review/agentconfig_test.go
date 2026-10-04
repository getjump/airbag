package review

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func TestWriteBackRefusesBranchSymlink(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1}`)
	// The agent replaces its copy with a symlink to some other JSON file
	// on the host that happens to hold an allowlisted key.
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	writeCfg(t, target, `{"numStartups":99,"userID":"from-elsewhere"}`)
	if err := os.MkdirAll(filepath.Dir(branchPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, branchPath); err != nil {
		t.Fatal(err)
	}

	if msgs := WriteBackConfigs(s); len(msgs) != 0 {
		t.Errorf("wrote back through a symlink: %v", msgs)
	}
	real := readCfg(t, realPath)
	if real["numStartups"] != float64(1) || real["userID"] != nil {
		t.Errorf("real file took values through the symlink: %v", real)
	}
	if _, err := os.Lstat(branchPath); err != nil {
		t.Errorf("branch symlink removed: %v", err)
	}
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath, Type: fs.ModeSymlink}
	if keys, _, ok := configKeyChange(c); !ok || len(keys) != 0 {
		t.Errorf("review read through the symlink: keys=%v ok=%v", keys, ok)
	}
	var b strings.Builder
	Diff(&b, c)
	if strings.Contains(b.String(), "from-elsewhere") || !strings.Contains(b.String(), "symlink -> "+target) {
		t.Errorf("diff of a symlink: %q", b.String())
	}
}

func TestWriteBackRefusesRealSymlink(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	target := filepath.Join(t.TempDir(), "dotfiles.json")
	writeCfg(t, target, `{"numStartups":1}`)
	if err := os.Symlink(target, realPath); err != nil {
		t.Fatal(err)
	}
	writeCfg(t, branchPath, `{"numStartups":2}`)
	WriteBackConfigs(s)
	if got := readCfg(t, target)["numStartups"]; got != float64(1) {
		t.Errorf("wrote through the real file's symlink: %v", got)
	}
	if fi, err := os.Lstat(realPath); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("real symlink replaced: %v", err)
	}
}

// An ordinary interactive run, as observed: counters change at the top
// level and under the current project's entry. All of it is benign, so
// all of it is written back and nothing is left for review.
func TestWriteBackProjectCounters(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1,"projects":{"/home/me/api":{"hasTrustDialogAccepted":true,"allowedTools":[],"lastCost":0.1,"lastSessionId":"a"}}}`)
	writeCfg(t, branchPath, `{"numStartups":2,"tipsHistory":{"x":1},"projects":{"/home/me/api":{"hasTrustDialogAccepted":true,"allowedTools":[],"lastCost":0.2,"lastSessionId":"b","lastDuration":5}}}`)

	WriteBackConfigs(s)

	real := readCfg(t, realPath)
	p := real["projects"].(map[string]any)["/home/me/api"].(map[string]any)
	if real["numStartups"] != float64(2) || p["lastCost"] != 0.2 || p["lastSessionId"] != "b" || p["lastDuration"] != float64(5) {
		t.Errorf("counters not written back: %v", real)
	}
	if p["hasTrustDialogAccepted"] != true {
		t.Errorf("trust lost: %v", p)
	}
	if _, err := os.Stat(branchPath); !os.IsNotExist(err) {
		t.Errorf("an ordinary run left the config in review: %v", err)
	}
}

// Next to the counters, the session granted a tool and wrote a sub-key
// the table does not know: those stay in the branch, by name.
func TestProjectPersistAndUnknownSubKeys(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"projects":{"/home/me/api":{"hasTrustDialogAccepted":true,"allowedTools":[],"lastCost":0.1}}}`)
	writeCfg(t, branchPath, `{"projects":{"/home/me/api":{"hasTrustDialogAccepted":true,"allowedTools":["Bash(*)"],"lastCost":0.2,"somethingNew":1}}}`)

	WriteBackConfigs(s)

	p := readCfg(t, realPath)["projects"].(map[string]any)["/home/me/api"].(map[string]any)
	if p["lastCost"] != 0.2 {
		t.Errorf("benign sub-key not written back: %v", p)
	}
	if len(p["allowedTools"].([]any)) != 0 || p["somethingNew"] != nil {
		t.Errorf("non-benign sub-keys reached the real file: %v", p)
	}
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
	changes, readable, ok := configChanges(c)
	if !ok || !readable {
		t.Fatalf("configChanges ok=%v readable=%v", ok, readable)
	}
	got := map[string]keyClass{}
	for _, ch := range changes {
		got[ch.String()] = ch.class
	}
	want := map[string]keyClass{
		"projects[/home/me/api].allowedTools": classPersist,
		"projects[/home/me/api].somethingNew": classUnknown,
	}
	if len(got) != len(want) {
		t.Errorf("changes = %v, want %v", got, want)
	}
	for k, c := range want {
		if got[k] != c {
			t.Errorf("%s: class %v, want %v (all: %v)", k, got[k], c, got)
		}
	}
}

// A session in a new project: its counters may go back, its trust
// decision may not.
func TestNewProjectEntryKeepsTrustInBranch(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":3}`)
	writeCfg(t, branchPath, `{"numStartups":3,"projects":{"/home/me/new":{"hasTrustDialogAccepted":true,"lastCost":0.3}}}`)

	WriteBackConfigs(s)

	p := readCfg(t, realPath)["projects"].(map[string]any)["/home/me/new"].(map[string]any)
	if p["lastCost"] != 0.3 || p["hasTrustDialogAccepted"] != nil {
		t.Errorf("real project entry = %v, want only the counter", p)
	}
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
	keys, persist, _ := configKeyChange(c)
	if !persist || !slices.Equal(keys, []string{"projects[/home/me/new].hasTrustDialogAccepted"}) {
		t.Errorf("review: keys=%v persist=%v", keys, persist)
	}
}

func TestKeyPathString(t *testing.T) {
	for path, want := range map[string]string{
		"mcpServers":                           "mcpServers",
		"projects\x00/home/me/a.b\x00lastCost": "projects[/home/me/a.b].lastCost",
		"tipsHistory\x00new-user-warmup":       "tipsHistory.new-user-warmup",
	} {
		if got := (keyChange{path: strings.Split(path, "\x00")}).String(); got != want {
			t.Errorf("%q: %q, want %q", path, got, want)
		}
	}
}
