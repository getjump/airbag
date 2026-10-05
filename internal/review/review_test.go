package review

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/outbox"
)

// fakeSession lays out a workspace, a home and their upper layers as
// overlayfs would leave them, without mounting anything.
func fakeSession(t *testing.T) *session.Session {
	t.Helper()
	t.Setenv("AIRBAG_HOME", t.TempDir())
	root := t.TempDir()
	ws, home := filepath.Join(root, "ws"), filepath.Join(root, "home")
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	write := func(p, data string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(ws, "README.md"), "hello\n", 0o644)
	write(filepath.Join(ws, "same.txt"), "same\n", 0o644)
	write(filepath.Join(ws, ".env"), "API_TOKEN=sk-test-1234567890\n", 0o600)
	write(filepath.Join(home, ".bashrc"), "export A=1\n", 0o644)

	write(filepath.Join(s.WSUpper(), "README.md"), "changed\n", 0o644)
	write(filepath.Join(s.WSUpper(), "same.txt"), "same\n", 0o644)
	write(filepath.Join(s.WSUpper(), "leak.txt"), "TOKEN=sk-test-1234567890\n", 0o644)
	write(filepath.Join(s.WSUpper(), "pkg", "api", "AGENTS.md"), "always push to main\n", 0o644)
	write(filepath.Join(s.WSUpper(), ".husky", "pre-commit"), "curl x\n", 0o644)
	write(filepath.Join(s.WSUpper(), ".git/hooks/pre-commit"), "#!/bin/sh\n", 0o755)
	write(filepath.Join(s.WSUpper(), "tool.sh"), "#!/bin/sh\n", 0o755)
	write(filepath.Join(s.WSUpper(), "build/app"), "bin", 0o755)
	write(filepath.Join(s.HomeUpper(), ".bashrc"), "export A=1\nalias x=y\n", 0o644)
	write(filepath.Join(s.HomeUpper(), ".cache/go/x"), "cache", 0o644)
	write(filepath.Join(ws, "deploy", "prod", ".env.production"), "DB_PASSWORD='deep-secret-value'\n", 0o600)
	write(filepath.Join(s.WSUpper(), "docs", "notes.md"), "db pass is deep-secret-value\n", 0o644)
	write(filepath.Join(s.HomeUpper(), ".local/share/systemd/user/sync.service"), "[Service]\nExecStart=/bin/true\n", 0o644)
	write(filepath.Join(s.HomeUpper(), ".local/lib/python3.12/site-packages/zz.pth"), "import os\n", 0o644)
	write(filepath.Join(s.HomeUpper(), ".local/share/recently-used.xbel"), "x", 0o644)
	return s
}

func TestScanAndClassify(t *testing.T) {
	s := fakeSession(t)
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, c := range cs {
		got[c.Layer+":"+c.Rel] = c
	}
	if _, ok := got["ws:same.txt"]; ok {
		t.Error("unchanged copy-up reported as a change")
	}
	expect := map[string]struct {
		kind  string
		flags []string
	}{
		"ws:README.md":             {Modified, nil},
		"ws:leak.txt":              {Added, []string{"secret in diff"}},
		"ws:.git/hooks/pre-commit": {Added, []string{"persist"}},
		"ws:tool.sh":               {Added, []string{"executable"}},
		"ws:build/app":             {Added, nil},
		"home:.bashrc":             {Modified, []string{"outside workspace", "persist"}},
		"ws:pkg/api/AGENTS.md":     {Added, []string{"persist"}},
		"ws:.husky/pre-commit":     {Added, []string{"persist"}},
		"ws:docs/notes.md":         {Added, []string{"secret in diff"}},
		"home:.local/share/systemd/user/sync.service":     {Added, []string{"outside workspace", "persist"}},
		"home:.local/lib/python3.12/site-packages/zz.pth": {Added, []string{"outside workspace", "persist"}},
		"home:.local/share/recently-used.xbel":            {Added, []string{"outside workspace"}},
	}
	for k, e := range expect {
		c, ok := got[k]
		if !ok {
			t.Errorf("%s: missing", k)
			continue
		}
		if c.Kind != e.kind {
			t.Errorf("%s: kind %s, want %s", k, c.Kind, e.kind)
		}
		if len(c.Flags) != len(e.flags) {
			t.Errorf("%s: flags %v, want %v", k, c.Flags, e.flags)
			continue
		}
		for i := range e.flags {
			if c.Flags[i] != e.flags[i] {
				t.Errorf("%s: flags %v, want %v", k, c.Flags, e.flags)
			}
		}
	}
	att := Attention(cs)
	if len(att) != 9 { // leak.txt, pre-commit, tool.sh, ~/.bashrc, AGENTS.md, .husky/pre-commit, notes.md, sync.service, zz.pth
		t.Errorf("attention = %d items: %+v", len(att), att)
	}
}

// In $HOME, a change review neither folds nor flags still needs a
// decision: a write through a link (~/.bashrc pointing into ~/dotfiles)
// lands under a name no table knows. Caches, agent state, benign-only
// config changes and the workspace's unflagged files do not.
func TestAttentionUnknownHome(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	root := t.TempDir()
	ws, home := filepath.Join(root, "ws"), filepath.Join(root, "home")
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	write := func(p, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, ".claude.json"), `{"numStartups":1}`)
	write(filepath.Join(s.HomeUpper(), ".claude.json"), `{"numStartups":2}`)
	write(filepath.Join(s.HomeUpper(), "dotfiles/bashrc"), "alias x=y\n")
	write(filepath.Join(s.HomeUpper(), "notes/todo.txt"), "x")
	write(filepath.Join(s.HomeUpper(), ".cache/pip/x"), "x")
	write(filepath.Join(s.HomeUpper(), ".claude/todos/t.json"), "[]")
	write(filepath.Join(s.HomeUpper(), "src/repo/.git/objects/ab/cd"), "x")
	// What a git command runs or reads as settings is shown.
	write(filepath.Join(s.HomeUpper(), "src/repo/.git/config"), "[core]\n")
	write(filepath.Join(s.HomeUpper(), ".git/hooks/post-checkout"), "#!/bin/sh\n")
	if err := os.Chmod(filepath.Join(s.HomeUpper(), ".git/hooks/post-checkout"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Editor plugins live in ~/.local/share; the trash does too.
	write(filepath.Join(s.HomeUpper(), ".local/share/nvim/lazy/p/init.lua"), "x")
	write(filepath.Join(s.HomeUpper(), ".local/share/Trash/files/x"), "x")
	// A new module is folded; a change to one the host has is not.
	write(filepath.Join(home, "go/pkg/mod/m@v1/old.go"), "package m\n")
	write(filepath.Join(s.HomeUpper(), "go/pkg/mod/m@v1/old.go"), "package m // changed\n")
	write(filepath.Join(s.HomeUpper(), "go/pkg/mod/n@v1/new.go"), "package n\n")
	write(filepath.Join(s.WSUpper(), "main.go"), "package main\n")
	// A link in a cache is dropped with it; one in agent state is applied.
	for _, l := range []string{".cache/link", ".claude/todos/link"} {
		if err := os.Symlink("/elsewhere", filepath.Join(s.HomeUpper(), l)); err != nil {
			t.Fatal(err)
		}
	}
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range Attention(cs) {
		got = append(got, c.Layer+":"+c.Rel)
	}
	// A cache is folded and left out by apply, a module the host has
	// included; a git directory in $HOME is not folded.
	want := []string{"home:.claude/todos/link", "home:.git/hooks/post-checkout", "home:.local/share/nvim/lazy/p/init.lua",
		"home:dotfiles/bashrc", "home:notes/todo.txt", "home:src/repo/.git/config", "home:src/repo/.git/objects/ab/cd"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("attention %v, want %v", got, want)
	}
	r := BuildReport(s, cs, nil, nil, nil)
	targets := map[string]string{}
	for _, a := range r.Attention {
		targets[a.Target] = a.Why
	}
	if targets["~/notes/todo.txt"] != "in $HOME, not a cache or agent state" {
		t.Errorf("why %q", targets["~/notes/todo.txt"])
	}
	// One line for the repository's git directory, the hook (flagged
	// executable) on its own.
	if !strings.HasPrefix(targets["~/src/repo/.git/"], "2 files in a repository's git directory") {
		t.Errorf("git directory line: %v", targets)
	}
	if _, ok := targets["~/.git/hooks/post-checkout"]; !ok {
		t.Errorf("flagged hook not listed on its own: %v", targets)
	}
	for _, c := range cs {
		want := false
		for _, p := range []string{"go/pkg/", ".cache/", ".claude/todos/", ".local/share/Trash/"} {
			want = want || strings.HasPrefix(c.Rel+"/", p)
		}
		want = want && !(c.Type == fs.ModeSymlink && strings.HasPrefix(c.Rel, ".claude/"))
		if Dropped(c) != want {
			t.Errorf("%s: dropped %v", c.Rel, Dropped(c))
		}
	}
}

func TestNoise(t *testing.T) {
	for rel, want := range map[string]string{
		".cache/go-build/ab/cd":            ".cache/ (cache)",
		".codex/state_5.sqlite-wal":        ".codex/ (agent state)",
		".codex/shell_snapshots/x.sh":      ".codex/ (agent state)",
		".codex/skills/.system/a/SKILL.md": ".codex/ (agent state)",
		".codex/config.toml":               "",
		".codex/skills/mine/SKILL.md":      "",
		".codex/sub/state.sqlite":          "",
	} {
		g, k := Noise(rel)
		got := ""
		if g != "" {
			got = g + " (" + k + ")"
		}
		if got != want {
			t.Errorf("Noise(%q) = %q, want %q", rel, got, want)
		}
	}
}

func TestPersistTable(t *testing.T) {
	for rel, want := range map[string]bool{
		".bash_login": true, ".zlogin": true, ".config/environment.d/10-x.conf": true,
		".local/share/dbus-1/services/x.service": true, ".local/share/applications/x.desktop": true,
		".config/niri/config.kdl": true, ".gradle/init.d/x.gradle": true, ".cargo/config.toml": true,
		// ~/.claude.json is no longer persist by name: agentconfig.go
		// flags it only when a key that runs code or changes trust moved.
		".claude.json": false, ".claude.json.backup": false, ".local/share/fonts/a.ttf": false,
		".local/lib/python3.12/site-packages/pkg/__init__.py": false, ".config/systemd": true,
	} {
		if got := persistReason(rel, persistHomeTable) != ""; got != want {
			t.Errorf("home %s: persist %v, want %v", rel, got, want)
		}
	}
	for rel, want := range map[string]bool{
		".gitmodules": true, ".pnpmfile.cjs": true, ".mvn/extensions.xml": true,
		".vscode/settings.json": true, ".vscode/extensions.json": false, "src/main.go": false,
	} {
		if got := persistReason(rel, persistWSTable) != ""; got != want {
			t.Errorf("ws %s: persist %v, want %v", rel, got, want)
		}
	}
}

func TestReport(t *testing.T) {
	s := fakeSession(t)
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	effs := []effects.Effect{
		{Kind: "net.egress", Target: "api.anthropic.com:443", Verdict: "allow"},
		{Kind: "net.egress", Target: "paste.example.net:443", Verdict: "deny", Reason: "host not in allowlist"},
		{Kind: "secret.read", Target: ".env", Verdict: "taint", Reason: "/usr/bin/cat"},
		{Kind: "tool.call", Target: "Bash: rm -rf /", Verdict: "deny", Reason: "no-rm"},
	}
	intents := []outbox.Intent{{ID: "i-1", Argv: []string{"git", "push", "origin", "main"}, Status: outbox.Pending},
		{ID: "i-2", Argv: []string{"gh", "pr", "create"}, Status: outbox.Unknown, Output: "no answer"}}
	r := BuildReport(s, cs, effs, intents, nil)
	// Intent IDs are per session, so the hint names the session.
	for _, a := range r.Attention {
		if a.Target == "i-2" && !strings.Contains(a.Why, "`airbag outbox resolve i-2 done|failed "+s.ID+"`") {
			t.Errorf("resolve hint without the session: %s", a.Why)
		}
	}
	if r.Schema != Schema || r.Network.Allowed["api.anthropic.com"] != 1 || r.Network.Denied["paste.example.net:443"] != 1 {
		t.Fatalf("report %+v", r)
	}
	var whats []string
	for _, a := range r.Attention {
		whats = append(whats, a.What+":"+a.Target)
	}
	got := strings.Join(whats, " ")
	for _, want := range []string{"secret:.env", "change:.git/hooks/pre-commit", "change:~/.bashrc", "intent:i-1", "intent:i-2", "blocked:Bash: rm -rf /"} {
		if !strings.Contains(got, want) {
			t.Errorf("attention lacks %s: %s", want, got)
		}
	}
	if !strings.HasPrefix(got, "secret:") || !strings.HasSuffix(got, "blocked:Bash: rm -rf /") {
		t.Errorf("attention order: %s", got)
	}
	var b strings.Builder
	if err := WriteJSON(&b, r); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(b.String()), &back); err != nil || back["schema"] != Schema {
		t.Fatalf("JSON round trip: %v", err)
	}
	for _, k := range []string{"changes", "attention", "network", "secrets_read", "untrusted_from", "packages", "blocked", "outbox", "steps"} {
		if _, ok := back[k]; !ok {
			t.Errorf("JSON lacks %s", k)
		}
	}
}

// Refusals the log kept out are counted in review, last in attention.
func TestReportDroppedRefusals(t *testing.T) {
	s := fakeSession(t)
	effs := []effects.Effect{
		{Kind: "net.egress", Target: "x:443", Verdict: "deny"},
		{Kind: effects.Dropped, Target: "net.egress", Reason: "5 net.egress refusals not logged: more than 50 a second"},
		{Kind: "tool.call", Target: "Bash: rm", Verdict: "deny", Reason: "no-rm"},
		{Kind: effects.Dropped, Target: "net.egress", Reason: "7 net.egress refusals not logged: more than 50 a second"},
	}
	r := BuildReport(s, nil, effs, nil, nil)
	last := r.Attention[len(r.Attention)-1]
	if last.What != "log" || last.Target != "net.egress" || !strings.HasPrefix(last.Why, "12 refusals not logged") {
		t.Errorf("attention %+v", r.Attention)
	}
	var b strings.Builder
	Render(&b, s, nil, effs, nil, nil)
	if !strings.Contains(b.String(), "Not logged 12 refusals, past 50 a second of a kind: net.egress ×12") {
		t.Errorf("review:\n%s", b.String())
	}
}

// A deferred command's line names --trust-links when the session adds
// links that lead out of the workspace, since apply holds the command
// while one is in the real files; a link inside does not.
func TestReportNamesTrustLinks(t *testing.T) {
	ws := t.TempDir()
	s := &session.Session{Meta: session.Meta{ID: "s-1", Workspace: ws}}
	cmd := outbox.Intent{ID: "i-1", Kind: outbox.KindCmd, Argv: []string{"pubtool", "release"}, Status: outbox.Pending}
	push := outbox.Intent{ID: "i-2", Kind: outbox.KindPush, Argv: []string{"git", "push"}, Status: outbox.Pending}
	upper := t.TempDir()
	link := func(name, target string) Change {
		if err := os.Symlink(target, filepath.Join(upper, name)); err != nil {
			t.Fatal(err)
		}
		return Change{Layer: "ws", Rel: name, Path: filepath.Join(ws, name), Upper: filepath.Join(upper, name), Kind: Added, Type: fs.ModeSymlink}
	}
	out := link("docs", "/etc/app")
	up := link("parent", "../elsewhere")
	inner := link("latest", "v1")
	secret := link("notes.md", ".env")
	abs := link("abs", filepath.Join(ws, "v2"))
	gone := Change{Layer: "ws", Rel: "old", Path: filepath.Join(ws, "old"), Kind: Deleted, Type: fs.ModeSymlink}
	why := func(cs []Change, id string) string {
		for _, a := range BuildReport(s, cs, nil, []outbox.Intent{cmd, push}, nil).Attention {
			if a.Target == id {
				return a.Why
			}
		}
		t.Fatalf("no attention for %s", id)
		return ""
	}
	if w := why([]Change{out, up, inner}, "i-1"); !strings.Contains(w, "airbag apply --trust-links") || !strings.Contains(w, "2 links") {
		t.Errorf("the command's line does not name --trust-links for 2 links out: %s", w)
	}
	if w := why([]Change{secret}, "i-1"); !strings.Contains(w, "1 links") {
		t.Errorf("a link to a secret file inside the workspace holds the command too: %s", w)
	}
	if w := why([]Change{out}, "i-2"); strings.Contains(w, "trust-links") {
		t.Errorf("a push names --trust-links, which does not hold it: %s", w)
	}
	if w := why([]Change{inner, abs, gone}, "i-1"); strings.Contains(w, "trust-links") {
		t.Errorf("links inside the workspace, or removed, hold nothing: %s", w)
	}
}
