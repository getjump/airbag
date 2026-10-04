package review

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

// A changed key the table does not know is neither written back nor
// persistence: review lists it plainly under attention, by name.
func TestReviewListsUnknownKeys(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1,"theme":"dark"}`)
	writeCfg(t, branchPath, `{"numStartups":2,"theme":"light"}`)
	WriteBackConfigs(s)

	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	att := Attention(cs)
	if len(att) != 1 || att[0].Rel != ".claude.json" {
		t.Fatalf("attention = %+v, want ~/.claude.json", att)
	}
	fl := att[0].Flags
	if !slices.Contains(fl, "unknown key(s): theme") {
		t.Errorf("flags %v lack the unknown key", fl)
	}
	if slices.Contains(fl, "persist") {
		t.Errorf("an unknown key was flagged as persistence: %v", fl)
	}
	var b strings.Builder
	WriteAttention(&b, BuildReport(s, cs, nil, nil, nil))
	if !strings.Contains(b.String(), "unknown key(s): theme") || strings.Contains(b.String(), "light") {
		t.Errorf("attention output: %q", b.String())
	}

	// Mixed with a persist key, both are named, each in its class.
	writeCfg(t, branchPath, `{"numStartups":2,"theme":"light","mcpServers":{"x":{}}}`)
	cs, _ = Scan(s)
	fl = Attention(cs)[0].Flags
	for _, want := range []string{"persist", "persist key(s): mcpServers", "unknown key(s): theme"} {
		if !slices.Contains(fl, want) {
			t.Errorf("mixed flags %v lack %q", fl, want)
		}
	}
}

// A null where an object was is not a deletion of every key in it: the
// whole subtree is one change, left in the branch, and nothing is
// written back from it.
func TestWriteBackNullStaysInBranch(t *testing.T) {
	for _, branch := range []string{
		`null`,
		`{"numStartups":1,"userID":"u","projects":null}`,
		`{"numStartups":1,"userID":"u","projects":{"/w":null}}`,
	} {
		s, realPath, branchPath := cfgSession(t)
		real := `{"numStartups":1,"userID":"u","projects":{"/w":{"lastCost":1,"allowedTools":[]}}}`
		writeCfg(t, realPath, real)
		writeCfg(t, branchPath, branch)
		if msgs := WriteBackConfigs(s); len(msgs) != 0 {
			t.Errorf("%s: wrote back %v", branch, msgs)
		}
		if b, _ := os.ReadFile(realPath); string(b) != real {
			t.Errorf("%s: real file changed to %s", branch, b)
		}
		if _, err := os.Stat(branchPath); err != nil {
			t.Errorf("%s: branch copy dropped: %v", branch, err)
		}
		c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
		if flags := configFlags(c); len(flags) == 0 {
			t.Errorf("%s: review shows nothing", branch)
		}
	}
}

// A benign key the agent removed is not removed from the real file: it
// stays a change for review.
func TestWriteBackNeverWritesDeletion(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1,"tipsHistory":{"x":1}}`)
	writeCfg(t, branchPath, `{"numStartups":2}`)
	WriteBackConfigs(s)
	got := readCfg(t, realPath)
	if got["numStartups"] != float64(2) || got["tipsHistory"] == nil {
		t.Fatalf("real file = %v, want the counter written and the removed key kept", got)
	}
	if _, err := os.Stat(branchPath); err != nil {
		t.Fatalf("branch copy dropped: %v", err)
	}
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
	if flags := strings.Join(configFlags(c), "; "); !strings.Contains(flags, "benign key(s): tipsHistory") {
		t.Fatalf("flags = %q, want the removed key listed", flags)
	}
}

// The account a login recorded decides which account and organization
// the host's next session uses, so a change to it is reviewed.
func TestAccountChangeIsReviewed(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"oauthAccount":{"emailAddress":"me@example.com"}}`)
	writeCfg(t, branchPath, `{"oauthAccount":{"emailAddress":"other@example.com"}}`)
	WriteBackConfigs(s)
	if got := readCfg(t, realPath); got["oauthAccount"].(map[string]any)["emailAddress"] != "me@example.com" {
		t.Fatalf("the account change was written back: %v", got)
	}
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
	if flags := strings.Join(configFlags(c), "; "); !strings.Contains(flags, "persist key(s): oauthAccount") {
		t.Fatalf("flags = %q, want the account flagged", flags)
	}
}

// A host edit during the session counts as one even when the editor kept
// an old modification time (cp -p, sync tools): it is the change time
// that tells, so the write-back is not recorded as airbag's own.
func TestHostEditWithOldMtimeIsNotOwnWrite(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1,"theme":"dark"}`)
	old := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(realPath, old, old); err != nil {
		t.Fatal(err)
	}
	writeCfg(t, branchPath, `{"numStartups":2,"theme":"dark","mcpServers":{}}`)
	WriteBackConfigs(s)
	if OwnWrite(s, realPath) {
		t.Fatal("a host edit with an old mtime was recorded as airbag's write")
	}
}

// writeAtomic replaces nothing when the file changed since it was read.
func TestWriteAtomicRefusesChangedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	writeCfg(t, p, `{"a":1}`)
	if err := writeAtomic(p, []byte(`{"a":2}`), func() bool { return false }); !errors.Is(err, errChanged) {
		t.Fatalf("err = %v, want errChanged", err)
	}
	if b, _ := os.ReadFile(p); string(b) != `{"a":1}` {
		t.Fatalf("file = %s, want it untouched", b)
	}
	if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 1 {
		t.Fatalf("left %v behind", ents)
	}
}

// Text Go's decoder would alter, and files over the limit, are not read
// as configs: they stay in the branch, flagged as unreadable.
func TestConfigTextIsRead(t *testing.T) {
	for name, body := range map[string]string{
		"surrogate escape": `{"numStartups":2,"k\ud800":1}`,
		"invalid utf-8":    "{\"numStartups\":2,\"k\xff\":1}",
		"oversize":         `{"numStartups":2,"pad":"` + strings.Repeat("x", maxConfig) + `"}`,
	} {
		s, realPath, branchPath := cfgSession(t)
		writeCfg(t, realPath, `{"numStartups":1}`)
		writeCfg(t, branchPath, body)
		if msgs := WriteBackConfigs(s); len(msgs) != 0 {
			t.Errorf("%s: wrote back %v", name, msgs)
		}
		c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
		if flags := strings.Join(configFlags(c), "; "); !strings.Contains(flags, "persist") {
			t.Errorf("%s: flags = %q, want persist", name, flags)
		}
	}
}

// After a write-back, the real file's new change time is airbag's own,
// until the host edits it again; when the host had edited it during the
// session, nothing is recorded, so apply still reports the conflict.
func TestOwnWriteRecordsOnlyAirbagsWrite(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1}`)
	s.Created = time.Now() // the real file predates the session
	writeCfg(t, branchPath, `{"numStartups":2,"mcpServers":{"x":{"command":"/bin/true"}}}`)
	WriteBackConfigs(s)
	if !OwnWrite(s, realPath) {
		t.Fatal("airbag's own write-back is not recognized")
	}
	if re, err := session.Load(s.Dir); err != nil || !OwnWrite(re, realPath) {
		t.Fatalf("the record is not saved with the session: %v", err)
	}
	if err := os.Chmod(realPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if OwnWrite(s, realPath) {
		t.Fatal("a later host chmod counts as airbag's write")
	}
	writeCfg(t, realPath, `{"numStartups":3}`)
	if OwnWrite(s, realPath) {
		t.Fatal("a later host edit counts as airbag's write")
	}

	s2, realPath2, branchPath2 := cfgSession(t)
	writeCfg(t, realPath2, `{"numStartups":1,"theme":"dark"}`) // a host edit during the session
	writeCfg(t, branchPath2, `{"numStartups":2,"mcpServers":{}}`)
	WriteBackConfigs(s2)
	if OwnWrite(s2, realPath2) {
		t.Fatal("a file the host also edited is recorded as airbag's write")
	}
}

// A benign key the host changed during the session and the agent did not
// keeps the host's value: the write-back merges three ways, from the base
// taken before the run.
func TestWriteBackKeepsHostChangeToUntouchedKey(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1,"tipsHistory":{"a":1}}`)
	SnapshotConfigs(s)
	writeCfg(t, branchPath, `{"numStartups":2,"tipsHistory":{"a":1}}`) // the agent's copy
	writeCfg(t, realPath, `{"numStartups":1,"tipsHistory":{"a":5}}`)   // a host session meanwhile
	WriteBackConfigs(s)
	got := readCfg(t, realPath)
	if got["numStartups"] != float64(2) || got["tipsHistory"].(map[string]any)["a"] != float64(5) {
		t.Fatalf("real file = %v, want the agent's counter and the host's tips", got)
	}
	if _, err := os.Stat(branchPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("branch copy kept (%v), want it dropped: nothing is left to review", err)
	}
	// A later run takes neither value for the agent's change again.
	writeCfg(t, branchPath, `{"numStartups":2,"tipsHistory":{"a":5}}`)
	writeCfg(t, realPath, `{"numStartups":7,"tipsHistory":{"a":5}}`)
	WriteBackConfigs(s)
	if got := readCfg(t, realPath); got["numStartups"] != float64(7) {
		t.Fatalf("real file = %v, the host's newer counter was overwritten", got)
	}
}

// When both changed a benign key, the agent's value is not written over
// the host's: it waits in the branch for review.
func TestWriteBackBothChangedWaitsForReview(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1}`)
	SnapshotConfigs(s)
	writeCfg(t, branchPath, `{"numStartups":2}`)
	writeCfg(t, realPath, `{"numStartups":3}`)
	WriteBackConfigs(s)
	if got := readCfg(t, realPath); got["numStartups"] != float64(3) {
		t.Fatalf("real file = %v, want the host's value kept", got)
	}
	if _, err := os.Stat(branchPath); err != nil {
		t.Fatalf("branch copy dropped: %v", err)
	}
}

// With no real file at the start of the run, the base is empty: a file the
// host creates meanwhile keeps its values where the agent's differ.
func TestWriteBackBaseWhenNoRealFile(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	SnapshotConfigs(s)
	writeCfg(t, branchPath, `{"numStartups":1,"userID":"u"}`)
	writeCfg(t, realPath, `{"numStartups":5}`) // a host session created it meanwhile
	WriteBackConfigs(s)
	got := readCfg(t, realPath)
	if got["numStartups"] != float64(5) || got["userID"] != "u" {
		t.Fatalf("real file = %v, want the host's counter kept and the agent's new id written", got)
	}
}

// A benign key the host added during the run, absent from the base and
// the branch, is not an agent's deletion: the branch copy takes it, so
// review shows only what the agent changed.
func TestWriteBackHostAddedKeyIsNotADeletion(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"userID":"u"}`)
	SnapshotConfigs(s)
	writeCfg(t, branchPath, `{"userID":"u","mcpServers":{}}`) // the agent's change
	writeCfg(t, realPath, `{"userID":"u","numStartups":4}`)   // a host session added a counter
	WriteBackConfigs(s)
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
	flags := strings.Join(configFlags(c), "; ")
	if strings.Contains(flags, "numStartups") || !strings.Contains(flags, "mcpServers") {
		t.Fatalf("flags = %q, want only the agent's mcpServers change", flags)
	}
	if got := readCfg(t, realPath); got["numStartups"] != float64(4) {
		t.Fatalf("real file = %v, want the host's counter kept", got)
	}
}

// A host-only change copied into the branch moves the base too: when
// the host changes the key again in a later run, the branch takes that
// as well, and the key never shows as the agent's change.
func TestWriteBackRebaseMovesTheBase(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"userID":"u","numStartups":1}`)
	SnapshotConfigs(s)
	writeCfg(t, branchPath, `{"userID":"u","numStartups":1,"mcpServers":{}}`) // the agent's change
	writeCfg(t, realPath, `{"userID":"u","numStartups":2}`)                   // a host session
	WriteBackConfigs(s)
	// A resumed run: the branch keeps its copy and the base.
	SnapshotConfigs(s)
	writeCfg(t, realPath, `{"userID":"u","numStartups":3}`)
	WriteBackConfigs(s)
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
	flags := strings.Join(configFlags(c), "; ")
	if strings.Contains(flags, "numStartups") || !strings.Contains(flags, "mcpServers") {
		t.Fatalf("flags = %q, want only the agent's mcpServers change", flags)
	}
	if got := readCfg(t, branchPath); got["numStartups"] != float64(3) {
		t.Fatalf("branch = %v, want the host's latest counter", got)
	}
}

// A benign key the host removed during the run, which the agent left
// as it was, is removed from the branch copy too: it is not the
// agent's addition.
func TestWriteBackHostRemovedKeyLeavesTheBranch(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"userID":"u","numStartups":1}`)
	SnapshotConfigs(s)
	writeCfg(t, branchPath, `{"userID":"u","numStartups":1,"mcpServers":{}}`) // the agent's change
	writeCfg(t, realPath, `{"userID":"u"}`)                                   // a host process removed the counter
	WriteBackConfigs(s)
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
	flags := strings.Join(configFlags(c), "; ")
	if strings.Contains(flags, "numStartups") || !strings.Contains(flags, "mcpServers") {
		t.Fatalf("flags = %q, want only the agent's mcpServers change", flags)
	}
	if got := readCfg(t, branchPath); got["numStartups"] != nil {
		t.Fatalf("branch = %v, want the host's removal taken", got)
	}
	if got := readCfg(t, realPath); got["numStartups"] != nil {
		t.Fatalf("real file = %v, want the counter still removed", got)
	}
}

func TestDeletePathNested(t *testing.T) {
	m, _ := topLevel([]byte(`{"projects":{"/a":{"x":1,"y":2}},"k":3}`))
	deletePath(m, []string{"projects", "/a", "x"})
	deletePath(m, []string{"projects", "/b", "x"}) // absent: no change
	deletePath(m, []string{"k", "z"})              // through a non-object: no change
	out, _ := marshalJSON(m, "")
	if want := `{"k":3,"projects":{"/a":{"y":2}}}`; canon(out) != canon([]byte(want)) {
		t.Fatalf("got %s, want %s", out, want)
	}
}

// A config the host removed during the run is not recreated by the
// write-back, even for a benign key the agent added: the removal is a
// host edit, and the branch copy waits for review.
func TestWriteBackHostRemovedFile(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"userID":"u","mcpServers":{"x":{}}}`)
	SnapshotConfigs(s)
	writeCfg(t, branchPath, `{"userID":"u","mcpServers":{"x":{}},"numStartups":1}`) // the agent adds a counter
	if err := os.Remove(realPath); err != nil {                                     // the host removes the file
		t.Fatal(err)
	}
	WriteBackConfigs(s)
	if _, err := os.Lstat(realPath); !os.IsNotExist(err) {
		t.Fatalf("the write-back recreated a config the host removed (err %v)", err)
	}
	if _, ok := s.WroteBack[realPath]; ok {
		t.Fatal("a write-back was recorded as airbag's own")
	}
	if _, err := os.Stat(branchPath); err != nil {
		t.Fatalf("the branch copy is gone: %v", err)
	}
}

// An empty config that existed at the start and that the host removed
// is told apart from one that never existed: it is not recreated
// either, and apply sees the removal.
func TestWriteBackHostRemovedEmptyFile(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{}`)
	SnapshotConfigs(s)
	writeCfg(t, branchPath, `{"numStartups":1}`)
	if err := os.Remove(realPath); err != nil {
		t.Fatal(err)
	}
	WriteBackConfigs(s)
	if _, err := os.Lstat(realPath); !os.IsNotExist(err) {
		t.Fatalf("the write-back recreated a config the host removed (err %v)", err)
	}
	if !RemovedOnHost(s, realPath) {
		t.Fatal("RemovedOnHost = false for a config the host removed")
	}
}

// A config absent at the start is not "removed on the host".
func TestRemovedOnHostNotForANewFile(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	SnapshotConfigs(s)
	writeCfg(t, branchPath, `{"mcpServers":{}}`)
	if RemovedOnHost(s, realPath) {
		t.Fatal("RemovedOnHost = true for a config that never existed")
	}
}

// With no real config at the start or at write-back, the agent's
// benign keys still create it: that is the first run, not a removal.
func TestWriteBackCreatesConfigWhenAbsent(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	SnapshotConfigs(s)
	writeCfg(t, branchPath, `{"numStartups":1}`)
	WriteBackConfigs(s)
	if got := readCfg(t, realPath); got["numStartups"] != float64(1) {
		t.Fatalf("real file = %v, want the agent's counter written", got)
	}
}

// A zero-byte config that existed at the start is not taken for an
// absent one: the host removing it is a removal, not a first run.
func TestWriteBackHostRemovedZeroByteFile(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, ``)
	SnapshotConfigs(s)
	writeCfg(t, branchPath, `{"numStartups":1}`)
	if err := os.Remove(realPath); err != nil {
		t.Fatal(err)
	}
	WriteBackConfigs(s)
	if _, err := os.Lstat(realPath); !os.IsNotExist(err) {
		t.Fatalf("the write-back recreated a config the host removed (err %v)", err)
	}
	if !RemovedOnHost(s, realPath) {
		t.Fatal("RemovedOnHost = false for a zero-byte config the host removed")
	}
}
