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
	writeCfg(t, realPath, `{"numStartups":1,"tipsHistory":{"x":1},"projects":{"/home/me/api":{"hasTrustDialogAccepted":true,"allowedTools":[],"lastCost":0.1,"lastSessionId":"a"}}}`)
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
	writeCfg(t, branchPath, `{"numStartups":1,"hooks":{"Stop":[]}}`)
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

// Every listed key path has the class its table gives it, and no path is
// in both tables.
func TestKeyTables(t *testing.T) {
	for _, cf := range jsonConfigs {
		for _, set := range []struct {
			pats []string
			want keyClass
		}{{cf.benign, classBenign}, {cf.persist, classPersist}} {
			for _, p := range set.pats {
				path := strings.Split(strings.ReplaceAll(p, "*", "/some/project"), ".")
				if c, listed, _ := cf.class(path); !listed || c != set.want {
					t.Errorf("%s %s: class %v listed %v, want %v", cf.path, p, c, listed, set.want)
				}
			}
		}
		for _, p := range cf.benign {
			if slices.Contains(cf.persist, p) {
				t.Errorf("%s: %s is both benign and persist", cf.path, p)
			}
		}
		// The keys that run code or change trust, pinned: dropping one
		// from the table would still show it, but as unknown.
		for _, p := range []string{
			"mcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers", "mcpContextUris",
			"permissions", "allowedTools", "hooks", "env", "apiKeyHelper",
			"customApiKeyResponses", "oauthAccount", "primaryApiKey", "bypassPermissionsModeAccepted",
			"projects.*.allowedTools", "projects.*.mcpServers", "projects.*.mcpContextUris",
			"projects.*.enabledMcpjsonServers", "projects.*.disabledMcpjsonServers",
			"projects.*.hasTrustDialogAccepted", "projects.*.hasClaudeMdExternalIncludesApproved",
		} {
			if !slices.Contains(cf.persist, p) {
				t.Errorf("%s: %s is not persist", cf.path, p)
			}
		}
	}
}

// A new project's entry, as the CLI first writes it, holds its listed
// keys with their empty defaults: that adds nothing, so it needs no
// decision. A non-empty value still does, and so does emptying a list
// that had entries.
func TestEmptyDefaultsAreNoChange(t *testing.T) {
	_, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1,"projects":{"/old":{"disabledMcpjsonServers":["x"]}}}`)
	writeCfg(t, branchPath, `{"numStartups":2,"projects":{"/old":{"disabledMcpjsonServers":[]},"/home/me/new":{"allowedTools":[],"mcpServers":{},"mcpContextUris":[],"enabledMcpjsonServers":[],"disabledMcpjsonServers":[],"hasTrustDialogAccepted":false,"hasClaudeMdExternalIncludesApproved":false,"lastCost":0}}}`)
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
	want := []string{"persist", `persist key(s): projects["/old"].disabledMcpjsonServers`}
	if got := configFlags(c); !slices.Equal(got, want) {
		t.Errorf("flags = %q, want %q", got, want)
	}
}

// Claude Code reads its legacy config, ~/.claude/.config.json, first
// when it exists: it is reviewed by key like ~/.claude.json.
func TestLegacyConfigPath(t *testing.T) {
	s, _, _ := cfgSession(t)
	writeCfg(t, filepath.Join(s.HomeUpper(), ".claude/.config.json"), `{"numStartups":1,"mcpServers":{"x":{"command":"evil"}}}`)
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel != ".claude/.config.json" {
			continue
		}
		if !slices.Contains(c.Flags, "persist key(s): mcpServers") {
			t.Errorf("flags = %v", c.Flags)
		}
		if d := diffOf(c); strings.Contains(d, "evil") {
			t.Errorf("diff printed a value: %q", d)
		}
		return
	}
	t.Fatalf("no change for the legacy config in %+v", cs)
}

// A config the agent made writable by other users is flagged: another
// user could add an MCP server to it. Narrower modes are not, nor group
// write when the group is the user's private one.
func TestConfigModeWidened(t *testing.T) {
	private := func(p string) bool {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return privateGroup(fileGID(fi))
	}
	for mode, flagged := range map[os.FileMode]bool{0o602: true, 0o666: true, 0o644: false, 0o600: false, 0o660: false} {
		s, realPath, branchPath := cfgSession(t)
		writeCfg(t, realPath, `{"numStartups":1}`)
		if mode == 0o660 {
			flagged = !private(realPath)
		}
		writeCfg(t, branchPath, `{"numStartups":1}`)
		if err := os.Chmod(branchPath, mode); err != nil {
			t.Fatal(err)
		}
		cs, err := Scan(s)
		if err != nil {
			t.Fatal(err)
		}
		var flags []string
		for _, c := range cs {
			if c.Rel == ".claude.json" {
				flags = c.Flags
			}
		}
		got := slices.ContainsFunc(flags, func(f string) bool { return strings.Contains(f, "writable by other users") })
		if got != flagged || (len(Attention(cs)) > 0) != flagged {
			t.Errorf("mode %04o: flags %v, attention %d", mode, flags, len(Attention(cs)))
		}
	}
}

// A directory where the config was is nothing review can read: it is
// flagged as the worst case, like a deletion.
func TestConfigDirectoryIsUnreadable(t *testing.T) {
	_, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1}`)
	if err := os.MkdirAll(branchPath, 0o700); err != nil {
		t.Fatal(err)
	}
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath, Type: fs.ModeDir, Kind: Replaced}
	if flags := configFlags(c); !slices.Contains(flags, "persist") {
		t.Errorf("flags = %q, want persist", flags)
	}
}

// A real config that is a symlink into $HOME (a dotfiles directory): a
// change written through the link lands on the link's target, which is
// reviewed by key like the config; a branch copy that replaced the link
// is compared with the file the link points to.
func TestSymlinkedConfig(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	target := filepath.Join(s.Home, "dotfiles", "claude.json")
	writeCfg(t, target, `{"numStartups":1}`)
	if err := os.Symlink("dotfiles/claude.json", realPath); err != nil {
		t.Fatal(err)
	}
	through := Change{Layer: "home", Rel: "dotfiles/claude.json", Path: target, Upper: filepath.Join(s.HomeUpper(), "dotfiles", "claude.json"), Kind: Modified}
	writeCfg(t, through.Upper, `{"numStartups":2,"mcpServers":{"x":{"command":"evil"}}}`)
	if flags := configFlags(through); !slices.Contains(flags, "persist key(s): mcpServers") {
		t.Errorf("written through the link: flags = %q", flags)
	}
	if d := diffOf(through); strings.Contains(d, "evil") || !strings.Contains(d, "benign key(s): numStartups") {
		t.Errorf("written through the link: diff = %q", d)
	}
	writeCfg(t, branchPath, `{"numStartups":2}`)
	replaced := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath, Kind: Modified}
	if flags := configFlags(replaced); len(flags) != 0 {
		t.Errorf("the link replaced by a counter change: flags = %q", flags)
	}
}

// A change to a shell snapshot the host already has is shell code a host
// session sources: flagged, listed and shown; a new snapshot is the
// sandbox session's own and stays folded. Any change to a session's env
// files counts, a new session's too: the host can resume it by id.
func TestHostShellStateIsFlagged(t *testing.T) {
	s, _, _ := cfgSession(t)
	writeCfg(t, filepath.Join(s.Home, ".claude/shell-snapshots/snapshot-bash-1.sh"), "export PATH=/usr/bin\n")
	writeCfg(t, filepath.Join(s.Home, ".claude/session-env/host-id/hook-0.sh"), "")
	for rel, body := range map[string]string{
		".claude/shell-snapshots/snapshot-bash-1.sh": "export PATH=/tmp/evil:/usr/bin\n",
		".claude/shell-snapshots/snapshot-bash-2.sh": "export PATH=/usr/bin\n",
		".claude/session-env/host-id/hook-1.sh":      "export X=1\n",
		".claude/session-env/sandbox-id/hook-0.sh":   "export Y=1\n",
	} {
		writeCfg(t, filepath.Join(s.HomeUpper(), rel), body)
	}
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		".claude/shell-snapshots/snapshot-bash-1.sh": true, ".claude/shell-snapshots/snapshot-bash-2.sh": false,
		".claude/session-env/host-id/hook-1.sh": true, ".claude/session-env/sandbox-id/hook-0.sh": true,
	}
	for _, c := range cs {
		w, ok := want[c.Rel]
		if !ok {
			continue
		}
		if got := slices.Contains(c.Flags, shellStateFlag) && slices.Contains(c.Flags, "persist"); got != w {
			t.Errorf("%s: flags %v, want flagged=%v", c.Rel, c.Flags, w)
		}
		if d := diffOf(c); strings.Contains(d, "export") != w {
			t.Errorf("%s: diff %q, want contents shown=%v", c.Rel, d, w)
		}
	}
	var b strings.Builder
	Render(&b, s, cs, nil, nil, nil)
	if !strings.Contains(b.String(), "~/.claude/shell-snapshots/snapshot-bash-1.sh") || strings.Contains(b.String(), "snapshot-bash-2.sh") {
		t.Errorf("review listing:\n%s", b.String())
	}
}

// A name with a line break is one quoted line in the review listing and
// in the attention list, so it cannot add a line that passes for another
// change.
func TestListQuotesNewlineNames(t *testing.T) {
	s, _, _ := cfgSession(t)
	writeCfg(t, filepath.Join(s.HomeUpper(), ".config/autostart/x\n  + ~/.cache/harmless.txt"), "[Desktop Entry]\n")
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	Render(&b, s, cs, nil, nil, nil)
	WriteAttention(&b, BuildReport(s, cs, nil, nil, nil))
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "+ ~/.cache/") {
			t.Fatalf("a name added a line:\n%s", b.String())
		}
	}
}

// holdsMemory reads directory names, so a home path holding glob
// characters still finds a project's memory.
func TestHoldsMemoryGlobCharacters(t *testing.T) {
	home := filepath.Join(t.TempDir(), "a[b]*?")
	writeCfg(t, filepath.Join(home, ".claude/projects/-x/memory/M.md"), "remember")
	for rel, real := range map[string]string{
		".claude":             filepath.Join(home, ".claude"),
		".claude/projects":    filepath.Join(home, ".claude/projects"),
		".claude/projects/-x": filepath.Join(home, ".claude/projects/-x"),
	} {
		if !holdsMemory(real, rel) {
			t.Errorf("%s: memory not found", rel)
		}
	}
}

// Only a key's own default stands for no key: an empty value of another
// type is a change, since JavaScript reads [] and {} as true.
func TestDefaultsAreTyped(t *testing.T) {
	for _, tc := range []struct{ real, branch, key string }{
		{`{"projects":{"/w":{}}}`, `{"projects":{"/w":{"hasTrustDialogAccepted":[]}}}`, `projects["/w"].hasTrustDialogAccepted`},
		{`{"projects":{"/w":{"hasTrustDialogAccepted":false}}}`, `{"projects":{"/w":{"hasTrustDialogAccepted":{}}}}`, `projects["/w"].hasTrustDialogAccepted`},
		{`{}`, `{"projects":{"/w":{"hasClaudeMdExternalIncludesApproved":{}}}}`, `projects["/w"].hasClaudeMdExternalIncludesApproved`},
		{`{}`, `{"projects":{"/w":{"allowedTools":{}}}}`, `projects["/w"].allowedTools`},
		{`{}`, `{"bypassPermissionsModeAccepted":[]}`, "bypassPermissionsModeAccepted"},
		{`{}`, `{"oauthAccount":{}}`, "oauthAccount"},
		{`{}`, `{"mcpServers":{}}`, "mcpServers"},
	} {
		_, realPath, branchPath := cfgSession(t)
		writeCfg(t, realPath, tc.real)
		writeCfg(t, branchPath, tc.branch)
		c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath}
		if flags := configFlags(c); !slices.Contains(flags, "persist key(s): "+tc.key) {
			t.Errorf("%s over %s: flags = %q", tc.branch, tc.real, flags)
		}
	}
}

// A new legacy config is read instead of ~/.claude.json, whose trust and
// settings then stop applying: that needs a decision.
func TestLegacyConfigShadows(t *testing.T) {
	s, realPath, _ := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1}`)
	writeCfg(t, filepath.Join(s.HomeUpper(), ".claude/.config.json"), `{"numStartups":1}`)
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel == ".claude/.config.json" && slices.Contains(c.Flags, "new, read instead of ~/.claude.json") {
			return
		}
	}
	t.Fatalf("changes = %+v", cs)
}

// A new config that other users can write is flagged like a widened one.
func TestNewConfigWritableByOthers(t *testing.T) {
	_, realPath, branchPath := cfgSession(t)
	writeCfg(t, branchPath, `{"numStartups":1}`)
	if err := os.Chmod(branchPath, 0o666); err != nil {
		t.Fatal(err)
	}
	c := Change{Layer: "home", Rel: ".claude.json", Path: realPath, Upper: branchPath, Kind: Added, Mode: 0o666}
	if flags := strings.Join(configFlags(c), "; "); !strings.Contains(flags, "writable by other users") {
		t.Errorf("flags = %q", flags)
	}
}

// Deleting or replacing a shell-state directory that holds the host's
// entries is flagged; one with nothing of the host's is not.
func TestHostShellStateDirectory(t *testing.T) {
	home := t.TempDir()
	writeCfg(t, filepath.Join(home, ".claude/shell-snapshots/snapshot-bash-1.sh"), "")
	for kind, want := range map[string]bool{Deleted: true, Replaced: true, Modified: false} {
		if got := touchesHostShellState(home, ".claude/shell-snapshots/", kind); got != want {
			t.Errorf("%s: %v, want %v", kind, got, want)
		}
	}
	if touchesHostShellState(t.TempDir(), ".claude/shell-snapshots/", Deleted) {
		t.Error("an empty host directory counted")
	}
}

// A config reached through a chain of links, or a linked directory on
// the way, resolves to its real file too.
func TestLinkedConfigChains(t *testing.T) {
	s, realPath, _ := cfgSession(t)
	h := s.Home
	writeCfg(t, filepath.Join(h, "src/dotfiles/claude.json"), `{"numStartups":1}`)
	symlink(t, "src/dotfiles", filepath.Join(h, "dotfiles"))
	symlink(t, "dotfiles/claude.json", filepath.Join(h, ".claude-link"))
	symlink(t, ".claude-link", realPath)
	target := filepath.Join(h, "src/dotfiles/claude.json")
	c := Change{Layer: "home", Rel: "src/dotfiles/claude.json", Path: target, Upper: filepath.Join(s.HomeUpper(), "src/dotfiles/claude.json"), Kind: Modified}
	writeCfg(t, c.Upper, `{"numStartups":2,"mcpServers":{"x":{"command":"evil"}}}`)
	if flags := configFlags(c); !slices.Contains(flags, "persist key(s): mcpServers") {
		t.Errorf("flags = %q", flags)
	}
	if d := diffOf(c); strings.Contains(d, "evil") {
		t.Errorf("diff printed a value: %q", d)
	}
}

// Group write on a config whose group is shared with other users is
// flagged.
func TestConfigGroupWritableShared(t *testing.T) {
	s, realPath, branchPath := cfgSession(t)
	writeCfg(t, realPath, `{"numStartups":1}`)
	writeCfg(t, branchPath, `{"numStartups":1}`)
	// A group other than the user's own: on most systems as root,
	// "daemon" (1) or "bin" (2).
	shared := -1
	for _, gid := range []int{1, 2, 100} {
		if !privateGroup(gid) && os.Chown(realPath, -1, gid) == nil {
			shared = gid
			break
		}
	}
	if shared < 0 {
		t.Skip("cannot give the config a shared group here")
	}
	if err := os.Chmod(branchPath, 0o660); err != nil {
		t.Fatal(err)
	}
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel == ".claude.json" && !slices.ContainsFunc(c.Flags, func(f string) bool { return strings.Contains(f, "writable by other users") }) {
			t.Errorf("group %d: flags %v", shared, c.Flags)
		}
	}
}

// A legacy config that replaces a dangling link is read for the first
// time too, though Scan sees the link it replaces and calls it Modified;
// one that replaces a readable file is not new.
func TestLegacyConfigReplacesDanglingLink(t *testing.T) {
	for _, tc := range []struct {
		name string
		real func(t *testing.T, p string)
		want bool
	}{
		{"dangling", func(t *testing.T, p string) { symlink(t, "nowhere.json", p) }, true},
		{"readable", func(t *testing.T, p string) { writeCfg(t, p, `{"numStartups":1}`) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, realPath, _ := cfgSession(t)
			writeCfg(t, realPath, `{"numStartups":1}`)
			legacy := filepath.Join(s.Home, ".claude/.config.json")
			tc.real(t, legacy)
			writeCfg(t, filepath.Join(s.HomeUpper(), ".claude/.config.json"), `{"numStartups":2}`)
			cs, err := Scan(s)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cs {
				if c.Rel == ".claude/.config.json" {
					if got := slices.Contains(c.Flags, "new, read instead of ~/.claude.json"); got != tc.want {
						t.Errorf("kind %s, flags %v", c.Kind, c.Flags)
					}
					return
				}
			}
			t.Fatalf("no change in %+v", cs)
		})
	}
}

// A link the agent puts in place of the host's shell-state directory
// redirects what a resumed host session sources: flagged, though Scan
// calls a directory turned link Modified.
func TestShellStateDirReplacedByLink(t *testing.T) {
	for _, dir := range []string{".claude/session-env", ".claude/shell-snapshots"} {
		t.Run(dir, func(t *testing.T) {
			s, _, _ := cfgSession(t)
			writeCfg(t, filepath.Join(s.Home, dir, "host-id/hook-0.sh"), "export X=1\n")
			writeCfg(t, filepath.Join(s.Home, ".claude/debug/payload/hook-0.sh"), "export PATH=/tmp/x\n")
			if err := os.MkdirAll(filepath.Join(s.HomeUpper(), ".claude"), 0o700); err != nil {
				t.Fatal(err)
			}
			symlink(t, filepath.Join(s.Home, ".claude/debug/payload"), filepath.Join(s.HomeUpper(), dir))
			cs, err := Scan(s)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cs {
				if c.Rel == dir {
					if !slices.Contains(c.Flags, shellStateFlag) {
						t.Errorf("kind %s, flags %v", c.Kind, c.Flags)
					}
					return
				}
			}
			t.Fatalf("no change at %s in %+v", dir, cs)
		})
	}
}
