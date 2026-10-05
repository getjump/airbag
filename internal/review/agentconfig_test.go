package review

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

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

// scanConfig scans s and returns its ~/.claude.json change.
func scanConfig(t *testing.T, s *session.Session) (Change, []Change) {
	t.Helper()
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Layer == "home" && c.Rel == ".claude.json" {
			return c, cs
		}
	}
	t.Fatalf("no ~/.claude.json change in %+v", cs)
	return Change{}, nil
}

func diffOf(c Change) string {
	var b strings.Builder
	Diff(&b, c)
	return b.String()
}

// An ordinary interactive run, as observed: counters change at the top
// level and under the current project's entry, and one is removed. All of
// it is benign: review lists the keys, by name, and asks for no decision.
// Nothing reaches the real file before apply.
func TestBenignConfigChangeNeedsNoDecision(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	real := `{"numStartups":1,"tipsHistory":{"x":1},"projects":{"/home/me/api":{"hasTrustDialogAccepted":true,"allowedTools":[],"lastCost":0.1,"lastSessionId":"a"}}}`
	writeCfg(t, realPath, real)
	writeCfg(t, branchPath, `{"numStartups":2,"projects":{"/home/me/api":{"hasTrustDialogAccepted":true,"allowedTools":[],"lastCost":0.2,"lastSessionId":"secret-b","lastDuration":5}}}`)

	c, cs := scanConfig(t, s)
	if att := Attention(cs); len(att) != 0 {
		t.Errorf("a benign-only change needs a decision: %+v", att)
	}
	for _, f := range c.Flags {
		if f != "outside workspace" {
			t.Errorf("benign-only change flagged %q", f)
		}
	}
	d := diffOf(c)
	for _, want := range []string{"numStartups", "tipsHistory", `projects["/home/me/api"].lastCost`, `projects["/home/me/api"].lastDuration`, `projects["/home/me/api"].lastSessionId`} {
		if !strings.Contains(d, want) {
			t.Errorf("diff %q lacks %s", d, want)
		}
	}
	if !strings.Contains(d, "benign key(s): ") || strings.Contains(d, "secret-b") {
		t.Errorf("diff %q: want benign key names, no values", d)
	}
	if b, _ := os.ReadFile(realPath); string(b) != real {
		t.Errorf("the real file changed before apply: %s", b)
	}
}

// Next to counters, the agent planted an MCP server: the change is
// persistence, named by key, and the counters ride along with no flag.
func TestMixedConfigChangeIsPersist(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1}`)
	writeCfg(t, branchPath, `{"numStartups":2,"mcpServers":{"x":{"command":"evil"}}}`)

	c, cs := scanConfig(t, s)
	if att := Attention(cs); len(att) != 1 || att[0].Rel != ".claude.json" {
		t.Fatalf("attention = %+v, want ~/.claude.json", att)
	}
	for _, want := range []string{"persist", "persist key(s): mcpServers"} {
		if !slices.Contains(c.Flags, want) {
			t.Errorf("flags %v lack %q", c.Flags, want)
		}
	}
	for _, f := range c.Flags {
		if strings.Contains(f, "numStartups") {
			t.Errorf("a benign key is a flag: %v", c.Flags)
		}
	}
	d := diffOf(c)
	if !strings.Contains(d, "persist key(s): mcpServers") || !strings.Contains(d, "benign key(s): numStartups") || strings.Contains(d, "evil") {
		t.Errorf("diff = %q", d)
	}
}

// A real file that does not exist yet compares as an empty object: the
// whole new file is shown by key, each in its class.
func TestNewConfigFileComparedToEmpty(t *testing.T) {
	s, _, branchPath := cfgSession(t)
	writeCfg(t, branchPath, `{"numStartups":1,"hooks":{}}`)
	c, _ := scanConfig(t, s)
	if !slices.Contains(c.Flags, "persist key(s): hooks") || slices.ContainsFunc(c.Flags, func(f string) bool { return strings.Contains(f, "numStartups") }) {
		t.Errorf("flags = %v", c.Flags)
	}
}

// Next to the counters, the session granted a tool and wrote a sub-key
// the table does not know: each is named, in its class.
func TestProjectPersistAndUnknownSubKeys(t *testing.T) {
	_, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"projects":{"/home/me/api":{"hasTrustDialogAccepted":true,"allowedTools":[],"lastCost":0.1}}}`)
	writeCfg(t, branchPath, `{"projects":{"/home/me/api":{"hasTrustDialogAccepted":true,"allowedTools":["Bash(*)"],"lastCost":0.2,"somethingNew":1}}}`)

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
		`projects["/home/me/api"].allowedTools`: classPersist,
		`projects["/home/me/api"].lastCost`:     classBenign,
		`projects["/home/me/api"].somethingNew`: classUnknown,
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

// A session in a new project: its counters are benign, its trust
// decision is not.
func TestNewProjectEntryTrustIsPersist(t *testing.T) {
	_, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":3}`)
	writeCfg(t, branchPath, `{"numStartups":3,"projects":{"/home/me/new":{"hasTrustDialogAccepted":true,"lastCost":0.3}}}`)
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
	want := []string{"persist", `persist key(s): projects["/home/me/new"].hasTrustDialogAccepted`}
	if got := configFlags(c); !slices.Equal(got, want) {
		t.Errorf("flags = %q, want %q", got, want)
	}
}

func TestKeyPathString(t *testing.T) {
	for path, want := range map[string]string{
		"mcpServers":                           "mcpServers",
		"projects\x00/home/me/a.b\x00lastCost": `projects["/home/me/a.b"].lastCost`,
		"tipsHistory\x00new-user-warmup":       "tipsHistory.new-user-warmup",
	} {
		if got := (keyChange{path: strings.Split(path, "\x00")}).String(); got != want {
			t.Errorf("%q: %q, want %q", path, got, want)
		}
	}
}

// A changed key the table does not know is not persistence: review lists
// it plainly under attention, by name.
func TestReviewListsUnknownKeys(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1,"theme":"dark"}`)
	writeCfg(t, branchPath, `{"numStartups":2,"theme":"light"}`)

	_, cs := scanConfig(t, s)
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
	if !strings.Contains(b.String(), "unknown key(s): theme") || strings.Contains(b.String(), "light") || strings.Contains(b.String(), "numStartups") {
		t.Errorf("attention output: %q", b.String())
	}

	// Mixed with a persist key, both are named, each in its class.
	writeCfg(t, branchPath, `{"numStartups":2,"theme":"light","mcpServers":{"x":{}}}`)
	_, cs = scanConfig(t, s)
	fl = Attention(cs)[0].Flags
	for _, want := range []string{"persist", "persist key(s): mcpServers", "unknown key(s): theme"} {
		if !slices.Contains(fl, want) {
			t.Errorf("mixed flags %v lack %q", fl, want)
		}
	}
}

// A null where an object was is not a deletion of every key in it, which
// would read as benign: it is one change of the whole subtree, and needs
// a decision.
func TestNullIsOneChange(t *testing.T) {
	for branch, want := range map[string]string{
		`null`: "not a readable regular JSON file",
		`{"numStartups":1,"userID":"u","projects":null}`:        "unknown key(s): projects",
		`{"numStartups":1,"userID":"u","projects":{"/w":null}}`: `unknown key(s): projects["/w"]`,
	} {
		_, realPath, branchPath := cfgSession(t)
		writeCfg(t, realPath, `{"numStartups":1,"userID":"u","projects":{"/w":{"lastCost":1,"allowedTools":[]}}}`)
		writeCfg(t, branchPath, branch)
		c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
		if flags := configFlags(c); !slices.Contains(flags, want) {
			t.Errorf("%s: flags = %q, want %q", branch, flags, want)
		}
	}
}

// The account a login recorded decides which account and organization
// the host's next session uses, so a change to it is persistence.
func TestAccountChangeIsReviewed(t *testing.T) {
	_, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"oauthAccount":{"emailAddress":"me@example.com"}}`)
	writeCfg(t, branchPath, `{"oauthAccount":{"emailAddress":"other@example.com"}}`)
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
	if flags := strings.Join(configFlags(c), "; "); !strings.Contains(flags, "persist key(s): oauthAccount") {
		t.Fatalf("flags = %q, want the account flagged", flags)
	}
}

// Text Go's decoder would alter, and files over the limit, are not read
// as configs: they are flagged as unreadable, the worst case.
func TestConfigTextIsRead(t *testing.T) {
	for name, body := range map[string]string{
		"malformed":        `{not valid json`,
		"surrogate escape": `{"numStartups":2,"k\ud800":1}`,
		"invalid utf-8":    "{\"numStartups\":2,\"k\xff\":1}",
		"oversize":         `{"numStartups":2,"pad":"` + strings.Repeat("x", maxConfig) + `"}`,
	} {
		_, realPath, branchPath := cfgSession(t)
		writeCfg(t, realPath, `{"numStartups":1}`)
		writeCfg(t, branchPath, body)
		c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
		if flags := strings.Join(configFlags(c), "; "); !strings.Contains(flags, "persist") {
			t.Errorf("%s: flags = %q, want persist", name, flags)
		}
	}
}

// The agent replaces its copy with a symlink to some other JSON file on
// the host: review does not read through it, and shows the link.
func TestConfigSymlinkIsNotRead(t *testing.T) {
	_, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1}`)
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	writeCfg(t, target, `{"numStartups":99,"userID":"from-elsewhere"}`)
	if err := os.MkdirAll(filepath.Dir(branchPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, branchPath); err != nil {
		t.Fatal(err)
	}
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath, Type: fs.ModeSymlink}
	if flags := configFlags(c); !slices.Contains(flags, "not a readable regular JSON file") {
		t.Errorf("flags = %q, want unreadable", flags)
	}
	if d := diffOf(c); strings.Contains(d, "from-elsewhere") || !strings.Contains(d, "symlink -> "+target) {
		t.Errorf("diff of a symlink: %q", d)
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

func TestProjectDirDeletionFlagsMemory(t *testing.T) {
	s, _, _ := cfgSession(t)
	writeCfg(t, filepath.Join(s.Home, ".claude/projects/-x/memory/M.md"), "remember")
	writeCfg(t, filepath.Join(s.Home, ".claude/projects/-y/t.jsonl"), "{}")
	for _, d := range []string{"-x", "-y"} {
		wo := filepath.Join(s.HomeUpper(), ".claude/projects", d)
		if err := os.MkdirAll(filepath.Dir(wo), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mknod(wo, unix.S_IFCHR, 0); err != nil {
			t.Skipf("cannot make a whiteout here: %v", err)
		}
	}
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	flags := map[string]bool{}
	for _, c := range cs {
		flags[c.Rel] = slices.Contains(c.Flags, "agent instructions")
	}
	if !flags[".claude/projects/-x"] {
		t.Errorf("deleting a project dir with memory is not flagged: %v", flags)
	}
	if flags[".claude/projects/-y"] {
		t.Errorf("deleting a project dir without memory is flagged: %v", flags)
	}
}

func TestCanonKeepsBigIntegers(t *testing.T) {
	if canon([]byte(`{"a":9007199254740992}`)) == canon([]byte(`{"a":9007199254740993}`)) {
		t.Fatal("two different large integers compare equal")
	}
	if canon([]byte(`{"b":1,"a":2}`)) != canon([]byte(`{"a":2, "b":1}`)) {
		t.Fatal("key order or spacing changes the canonical form")
	}
}

// Only Claude Code's backups beside the config are shown without
// contents: a file elsewhere with such a name is shown in full.
func TestDiffShowsConfigLookalikesElsewhere(t *testing.T) {
	dir := t.TempDir()
	upper := filepath.Join(dir, ".claude.json.desktop")
	writeCfg(t, upper, "Exec=/tmp/run-me\n")
	var b strings.Builder
	Diff(&b, Change{Layer: "home", Rel: ".config/autostart/.claude.json.desktop", Path: filepath.Join(dir, "absent"), Upper: upper, Kind: Added})
	if !strings.Contains(b.String(), "run-me") {
		t.Fatalf("diff hid an autostart file named like a config backup: %q", b.String())
	}
	b.Reset()
	Diff(&b, Change{Layer: "home", Rel: ".claude.json.backup", Path: filepath.Join(dir, "absent"), Upper: upper, Kind: Added})
	if strings.Contains(b.String(), "run-me") {
		t.Fatalf("diff showed a config backup's contents: %q", b.String())
	}
}

// A key name the agent chose cannot add lines to review or pass for
// another key: control characters, quotes and brackets are quoted.
func TestKeyNamesStayOneLine(t *testing.T) {
	for _, path := range [][]string{{"x\nfake review line"}, {"projects", "/a]\nmcpServers[x"}, {"a\u202eb"}} {
		got := keyChange{path: path}.String()
		if strings.ContainsAny(got, "\n\r\u202e") {
			t.Errorf("key %q renders as %q", path, got)
		}
	}
	if got := (keyChange{path: []string{"projects", "/home/me/api", "allowedTools"}}).String(); got != `projects["/home/me/api"].allowedTools` {
		t.Errorf("an ordinary path renders as %q", got)
	}
	// A key that only looks like a path, or a list, is told apart.
	for path, want := range map[string]string{
		"projects.foo.allowedTools": `["projects.foo.allowedTools"]`,
		"mcpServers, hooks":         `["mcpServers, hooks"]`,
	} {
		if got := (keyChange{path: []string{path}}).String(); got != want {
			t.Errorf("top-level key %q renders as %q, want %q", path, got, want)
		}
	}
}

// A link target or a path the agent chose cannot add lines to the diff:
// one with a newline is shown quoted on one line.
func TestDiffQuotesMultilineNames(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "l")
	if err := os.Symlink("x\n+ fake reviewed change", link); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	Diff(&b, Change{Layer: "ws", Rel: "a\n+++ b/other", Path: filepath.Join(dir, "absent"), Upper: link, Kind: Added, Type: fs.ModeSymlink})
	for _, line := range strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n") {
		if strings.HasPrefix(line, "+ fake") || strings.HasPrefix(line, "+++ b/other") {
			t.Fatalf("an agent-chosen name added a diff line: %q", b.String())
		}
	}
	if lines := strings.Count(b.String(), "\n"); lines != 3 {
		t.Fatalf("diff has %d lines, want 3: %q", lines, b.String())
	}
}
