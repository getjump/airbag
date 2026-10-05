package review

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/steps"
	"github.com/getjump/airbag/outbox"
)

// Noise in $HOME: caches and agent state, folded into one line per
// group and left out by apply (a download cache holds code a host build
// runs as it is, so what is folded must not reach the host). A match
// ending in "/" is a directory prefix and its own group; others are
// path.Match patterns. The first match counts.
var homeNoise = []struct{ match, group, kind string }{
	{".cache/", "", "cache"}, {".npm/", "", "cache"}, {"go/pkg/", "", "cache"},
	{".cargo/registry/", "", "cache"}, {".cargo/git/", "", "cache"},
	{".m2/repository/", "", "cache"}, {".gradle/caches/", "", "cache"},
	{".gradle/wrapper/dists/", "", "cache"}, {".gradle/daemon/", "", "cache"},
	{".yarn/berry/cache/", "", "cache"}, {".bun/install/cache/", "", "cache"},
	{".nuget/packages/", "", "cache"}, {".config/go/telemetry/", "", "cache"},
	// Not all of ~/.local/share: it holds editor plugins (nvim) and
	// dotfile managers' sources (chezmoi), which a user may want
	// applied.
	{".local/share/Trash/", "", "cache"}, {".local/share/recently-used.xbel", ".local/share/", "cache"},
	{".local/share/zoxide/", "", "cache"}, {".local/share/pnpm/store/", "", "cache"},
	{".local/share/virtualenv/", "", "cache"},
	{".local/state/", "", "cache"}, {".rustup/", "", "cache"},
	// Codex keeps its state in SQLite next to config.toml; config.toml,
	// AGENTS.md, rules and user skills stay visible.
	{".codex/.tmp/", ".codex/", "agent state"}, {".codex/tmp/", ".codex/", "agent state"},
	{".codex/thread-writer-locks/", ".codex/", "agent state"}, {".codex/shell_snapshots/", ".codex/", "agent state"},
	{".codex/skills/.system/", ".codex/", "agent state"}, {".codex/*.sqlite*", ".codex/", "agent state"},
	{".codex/installation_id", ".codex/", "agent state"}, {".codex/.sandbox_migration", ".codex/", "agent state"},
	{".codex/version.json", ".codex/", "agent state"}, {".codex/models_cache.json", ".codex/", "agent state"},
	// Claude Code state that now goes through the branch (only the
	// current workspace's transcripts pass through). settings.json,
	// hooks, skills, CLAUDE.md and a project's memory/ are flagged, so
	// they are not folded here; everything below is caches and logs,
	// except shell snapshots and session env files, which the CLI
	// sources: a change to one the host already has is flagged
	// (hostShellState), so it is not folded either.
	{".claude/projects/", ".claude/", "agent state"}, {".claude/sessions/", ".claude/", "agent state"},
	{".claude/session-env/", ".claude/", "agent state"}, {".claude/shell-snapshots/", ".claude/", "agent state"},
	{".claude/file-history/", ".claude/", "agent state"}, {".claude/todos/", ".claude/", "agent state"},
	{".claude/statsig/", ".claude/", "agent state"}, {".claude/backups/", ".claude/", "agent state"},
	{".claude/debug/", ".claude/", "agent state"}, {".claude/ide/", ".claude/", "agent state"},
	{".claude/plans/", ".claude/", "agent state"},
}

const maxListed = 40

func Render(w io.Writer, s *session.Session, cs []Change, effs []effects.Effect, intents []outbox.Intent, sts []steps.Step) {
	dur := "running"
	if !s.Ended.IsZero() {
		dur = s.Ended.Sub(s.Created).Round(time.Second).String()
	}
	fmt.Fprintf(w, "Session %s · %s · %s · exit %d · %s\n\n", s.ID, strings.Join(s.Argv, " "), dur, s.ExitCode, s.Status)

	var ws, home []Change
	for _, c := range cs {
		if c.Layer == "ws" {
			ws = append(ws, c)
		} else {
			home = append(home, c)
		}
	}

	fmt.Fprintf(w, "Workspace  %s\n", s.Workspace)
	var gitInternal int
	var listed []Change
	for _, c := range ws {
		if strings.HasPrefix(c.Rel, ".git/") && len(c.Flags) == 0 {
			gitInternal++
			continue
		}
		listed = append(listed, c)
	}
	a, m, d := counts(listed)
	line := fmt.Sprintf("  Files    +%d ~%d -%d", a, m, d)
	if gitInternal > 0 {
		line += fmt.Sprintf("    (git internals: %d files)", gitInternal)
	}
	fmt.Fprintln(w, line)
	list(w, listed, "")

	if s.OverHome {
		fmt.Fprintf(w, "\nHome       %d changes outside the workspace\n", len(home))
		lines := map[string]int{}
		var shown []Change
		for _, c := range home {
			if line := folded(c); line != "" {
				lines[line]++
				continue
			}
			shown = append(shown, c)
		}
		list(w, shown, "~/")
		for _, dir := range sortedKeys(lines) {
			fmt.Fprintf(w, "  · ~/%s %d files\n", dir, lines[dir])
		}
	}

	allowed, denied, cut := map[string]int{}, map[string]int{}, map[string]int{}
	for _, e := range effs {
		if e.Kind != "net.egress" && e.Kind != "net.tcp" {
			continue
		}
		host, _, err := net.SplitHostPort(e.Target)
		if err != nil {
			host = e.Target
		}
		switch e.Verdict {
		case "deny", "ask":
			denied[e.Target]++
		case "cut":
			cut[e.Target]++
		default:
			allowed[host]++
		}
	}
	var reads []string
	for _, e := range effs {
		if e.Kind == "secret.read" {
			reads = append(reads, fmt.Sprintf("%s by %s", e.Target, e.Reason))
		}
	}
	if len(reads) > 0 {
		fmt.Fprintf(w, "\nSecrets    read: %s\n           egress was limited to model APIs and cached packages from then on\n", strings.Join(reads, ", "))
	}
	var untrusted []string
	seenU := map[string]bool{}
	for _, e := range effs {
		if e.Kind == "label" && e.Verdict == "untrusted" && !seenU[e.Target] {
			seenU[e.Target] = true
			untrusted = append(untrusted, e.Target)
		}
	}
	if len(untrusted) > 0 {
		fmt.Fprintf(w, "\nUntrusted  input pulled from: %s\n", strings.Join(untrusted, ", "))
	}
	var pkgs []string
	seenPkg := map[string]bool{}
	for _, e := range effs {
		if e.Kind == "pkg.fetch" && !seenPkg[e.Target] {
			seenPkg[e.Target] = true
			pkgs = append(pkgs, e.Target)
		}
	}
	if len(pkgs) > 0 {
		fmt.Fprintf(w, "\nPackages   %d fetched through the mirror\n", len(pkgs))
		for i, p := range pkgs {
			if i == maxListed {
				fmt.Fprintf(w, "  … and %d more\n", len(pkgs)-maxListed)
				break
			}
			fmt.Fprintf(w, "  %s\n", p)
		}
	}
	fmt.Fprintf(w, "\nNetwork    %d allowed%s\n", total(allowed), hostList(allowed))
	if len(denied) > 0 {
		fmt.Fprintf(w, "           %d denied%s\n", total(denied), hostList(denied))
	}
	if len(cut) > 0 {
		fmt.Fprintf(w, "           %d cut when a secret was read%s\n", total(cut), hostList(cut))
	}
	renderRequests(w, effs)

	if len(sts) > 0 {
		renderSteps(w, sts)
	}
	renderShell(w, effs)
	var blocked []effects.Effect
	for _, e := range effs {
		if (e.Verdict == "deny" || e.Verdict == "ask") && e.Kind != "net.egress" {
			blocked = append(blocked, e)
		}
	}
	if len(blocked) > 0 {
		fmt.Fprintf(w, "\nBlocked    %d by policy\n", len(blocked))
		for _, e := range blocked {
			fmt.Fprintf(w, "  %-4s %-40s %s\n", e.Verdict, clip(e.Target, 40), e.Reason)
		}
	}
	dropped := map[string]int{}
	for _, e := range effs {
		if e.Kind == effects.Dropped {
			dropped[e.Target] += effects.DroppedCount(e)
		}
	}
	if len(dropped) > 0 {
		fmt.Fprintf(w, "\nNot logged %d refusals, past %d a second of a kind%s\n", total(dropped), effects.RefuseRate, hostList(dropped))
	}

	fmt.Fprintf(w, "\nOutbox     %d\n", len(intents))
	secrets := knownSecrets(s.Workspace)
	for _, in := range intents {
		fmt.Fprintf(w, "  %-4s %-44s %s\n", in.ID, outbox.Line(in.Argv), in.Status)
		if in.Request != nil && in.Request.PullRequest != nil {
			p := in.Request.PullRequest
			fmt.Fprintf(w, "       GitHub %s: %s → %s at %s\n       request %s; frozen body available in airbag outbox\n", p.Repository, p.Head, p.Base, p.HeadCommit, in.RequestDigest)
		}
		if len(in.Files) > 0 {
			fmt.Fprintf(w, "       runs only on these as queued: %s\n", strings.Join(fileNames(in.Files), ", "))
		}
		if intentHasSecret(in, secrets) {
			fmt.Fprintf(w, "       ! carries a value from a secret file\n")
		}
	}

	if att := attentionLines(cs); len(att) > 0 {
		fmt.Fprintf(w, "\nAttention\n")
		for _, a := range att {
			if a.c == nil {
				fmt.Fprintf(w, "  ! %-40s %s\n", "~/"+a.group, gitDirWhy(a.n))
				continue
			}
			fmt.Fprintf(w, "  ! %-40s %s\n", display(*a.c), attentionWhy(*a.c))
		}
	}
	if d > 50 {
		fmt.Fprintf(w, "  ! %d files deleted in the workspace\n", d)
	}
	fmt.Fprintf(w, "\nNext: airbag diff [path] · airbag apply [-i] · airbag discard\n")
}

func counts(cs []Change) (a, m, d int) {
	for _, c := range cs {
		if c.IsDir() && c.Kind == Added {
			continue // counted through its files
		}
		switch c.Kind {
		case Added:
			a++
		case Modified, Replaced:
			m++
		case Deleted:
			d++
		}
	}
	return
}

func list(w io.Writer, all []Change, prefix string) {
	var cs []Change
	for _, c := range all {
		// New directories are implied by the files inside them.
		if !(c.IsDir() && c.Kind == Added && len(c.Flags) <= 1) {
			cs = append(cs, c)
		}
	}
	for i, c := range cs {
		if i == maxListed {
			fmt.Fprintf(w, "  … and %d more\n", len(cs)-maxListed)
			return
		}
		mark := map[string]string{Added: "+", Modified: "~", Deleted: "-", Replaced: "!"}[c.Kind]
		name := prefix + c.Rel
		if c.IsDir() {
			name += "/"
		}
		name = OneLine(name)
		flags := ""
		if f := withoutOutside(c.Flags); len(f) > 0 {
			flags = "  " + strings.Join(f, ", ")
		}
		fmt.Fprintf(w, "  %s %s%s\n", mark, name, flags)
	}
}

func display(c Change) string {
	if c.Layer == "home" {
		return OneLine("~/" + c.Rel)
	}
	return OneLine(c.Rel)
}

// OneLine quotes a name the agent chose (a path, a link target) when it
// holds a line break: the terminal-safe writer escapes other control
// characters but keeps newlines, so a raw one could add lines that pass
// for other changes.
func OneLine(s string) string {
	if strings.ContainsAny(s, "\n\r") {
		return strconv.Quote(s)
	}
	return s
}

func flagged(c Change) bool { return len(withoutOutside(c.Flags)) > 0 }

// folded returns the line review folds a change in $HOME into, "" when
// the change is listed on its own. Apply leaves what is folded out
// (Dropped), so the fold needs no decision. A cache is folded whatever
// it holds, executables and links included. Agent state is folded
// unless it carries a flag (memory, shell code a host session sources)
// or is a link, which would lead a later session's path somewhere
// else: those are applied. Git internals in $HOME are not folded:
// objects and refs go with the config and hooks a git command runs.
func folded(c Change) string {
	if c.Layer != "home" {
		return ""
	}
	group, kind := noise(c.Rel)
	if group == "" || kind != "cache" && (flagged(c) || c.Type == fs.ModeSymlink) {
		return ""
	}
	return group + "… (" + kind + ", not applied)"
}

// Dropped reports whether apply leaves a change out: review folds it as
// a cache or agent state.
func Dropped(c Change) bool { return folded(c) != "" }

// DroppedState reports whether apply leaves a change out as agent state
// rather than as a cache.
func DroppedState(c Change) bool {
	_, kind := noise(c.Rel)
	return Dropped(c) && kind == "agent state"
}

// attentionLine is one line of the attention list: a change, or the
// unflagged changes in one git directory in $HOME, counted.
type attentionLine struct {
	c     *Change
	group string
	n     int
}

func attentionLines(cs []Change) []attentionLine {
	var out []attentionLine
	at := map[string]int{}
	for _, c := range Attention(cs) {
		if c.Layer == "home" && !flagged(c) {
			if repo := GitDir(c.Rel); repo != "" {
				if i, ok := at[repo]; ok {
					out[i].n++
				} else {
					at[repo] = len(out)
					out = append(out, attentionLine{group: repo, n: 1})
				}
				continue
			}
		}
		out = append(out, attentionLine{c: &c})
	}
	return out
}

// gitDirWhy says why a git directory in $HOME needs a decision.
func gitDirWhy(n int) string {
	return fmt.Sprintf("%d files in a repository's git directory in $HOME (its config and hooks run with the next git command there)", n)
}

// attentionWhy says why a change needs a decision.
func attentionWhy(c Change) string {
	if why := strings.Join(withoutOutside(c.Flags), ", "); why != "" {
		return why
	}
	return "in $HOME, not a cache or agent state"
}

func withoutOutside(fl []string) []string {
	var out []string
	for _, f := range fl {
		if f != "outside workspace" {
			out = append(out, f)
		}
	}
	return out
}

// GitDir returns the repository dir for paths inside .git or *.git.
func GitDir(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i, p := range parts[:len(parts)-1] {
		if p == ".git" || strings.HasSuffix(p, ".git") {
			return strings.Join(parts[:i+1], "/") + "/"
		}
	}
	return ""
}

// Noise returns the folding group of a path in $HOME, "" when the path
// is not noise, and what kind of noise it is.
func Noise(rel string) (group, kind string) { return noise(rel) }

func noise(rel string) (group, kind string) {
	for _, n := range homeNoise {
		var hit bool
		if strings.HasSuffix(n.match, "/") {
			hit = strings.HasPrefix(rel+"/", n.match)
		} else {
			hit, _ = path.Match(n.match, rel)
		}
		if hit {
			if n.group == "" {
				return n.match, n.kind
			}
			return n.group, n.kind
		}
	}
	return "", ""
}

func total(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func hostList(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	keys := sortedKeys(m)
	sort.SliceStable(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] })
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s ×%d", k, m[k]))
	}
	return ": " + strings.Join(parts, ", ")
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// renderSteps lists the agent's tool calls that changed something.
func renderSteps(w io.Writer, sts []steps.Step) {
	var changed []steps.Step
	for _, st := range sts {
		if len(st.Changes) > 0 {
			changed = append(changed, st)
		}
	}
	// A failed call can report twice (PostToolUseFailure and PostToolUse).
	ids := map[string]bool{}
	changingIDs := map[string]bool{}
	for _, st := range sts {
		if st.Tool == "-" {
			continue
		}
		id := st.ID
		if id == "" {
			id = fmt.Sprint(st.N)
		}
		ids[id] = true
		if len(st.Changes) > 0 {
			changingIDs[id] = true
		}
	}
	calls, changing := len(ids), len(changingIDs)
	fmt.Fprintf(w, "\nSteps      %d tool calls, %d of them changed files\n", calls, changing)
	for i, st := range changed {
		if i == maxListed {
			fmt.Fprintf(w, "  … and %d more\n", len(changed)-maxListed)
			return
		}
		var shown []string
		git, more := 0, 0
		noise := map[string]int{}
		for _, c := range st.Changes {
			mark, rest := c[:1], c[1:]
			layer, path, _ := strings.Cut(rest, ":")
			if GitDir(path) != "" {
				git++
				continue
			}
			if _, kind := Noise(path); layer == "home" && kind != "" {
				noise[kind]++
				continue
			}
			if layer == "home" {
				path = "~/" + path
			}
			if len(shown) == 3 {
				more++
				continue
			}
			shown = append(shown, mark+path)
		}
		if more > 0 {
			shown = append(shown, fmt.Sprintf("+%d more", more))
		}
		if git > 0 {
			shown = append(shown, fmt.Sprintf("(git: %d files)", git))
		}
		for _, kind := range sortedKeys(noise) {
			shown = append(shown, fmt.Sprintf("(%s: %d files)", kind, noise[kind]))
		}
		fmt.Fprintf(w, "  #%-3d %-6s %-38s → %s\n", st.N, st.Tool, clip(st.Summary, 38), strings.Join(shown, " "))
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Predicted effects worth a look before applying.
var notable = []string{"fs.delete", "net.egress", "intent.", "persist", "fs.exec_bit"}

// renderShell lists shell commands whose models predict risky effects.
func renderShell(w io.Writer, effs []effects.Effect) {
	total := 0
	type row struct{ cmd, pred string }
	var rows []row
	for _, e := range effs {
		if e.Kind != "proc.exec" {
			continue
		}
		total++
		var hits []string
		for _, p := range e.Predict {
			for _, n := range notable {
				if strings.HasPrefix(p, n) {
					hits = append(hits, p)
					break
				}
			}
		}
		if len(hits) > 0 {
			rows = append(rows, row{e.Target, strings.Join(hits, ", ")})
		}
	}
	if total == 0 {
		return
	}
	fmt.Fprintf(w, "\nShell      %d commands, %d worth a look\n", total, len(rows))
	for i, r := range rows {
		if i == maxListed {
			fmt.Fprintf(w, "  … and %d more\n", len(rows)-maxListed)
			return
		}
		fmt.Fprintf(w, "  $ %-40s → %s\n", clip(r.cmd, 40), r.pred)
	}
}

// Diff writes a unified diff of one change.
func Diff(w io.Writer, c Change) {
	if c.IsDir() {
		fmt.Fprintf(w, "%s %s/ (directory %s)\n", map[string]string{Added: "+", Deleted: "-", Replaced: "!"}[c.Kind], display(c), c.Kind)
		return
	}
	// A symlink is shown by its target. diff would follow it, and print
	// whatever host file the agent pointed it at.
	if c.Type == fs.ModeSymlink {
		old, cur := "", ""
		if c.Kind != Added {
			old, _ = os.Readlink(c.Path)
		}
		if c.Kind != Deleted {
			cur, _ = os.Readlink(c.Upper)
		}
		fmt.Fprintf(w, "--- a/%s\n+++ b/%s\n", display(c), display(c))
		if old != "" {
			fmt.Fprintf(w, "-symlink -> %s\n", OneLine(old))
		}
		if cur != "" {
			fmt.Fprintf(w, "+symlink -> %s\n", OneLine(cur))
		}
		return
	}
	// Agent state and copies of an agent config (Claude Code keeps
	// backups of ~/.claude.json) may hold tokens: no contents.
	// Only Claude Code's own backups, beside the config in $HOME: an
	// agent file elsewhere with such a name is shown like any other.
	if c.Layer == "home" && (!strings.Contains(filepath.ToSlash(c.Rel), "/") && strings.HasPrefix(c.Rel, ".claude.json") && configFor(filepath.ToSlash(c.Rel)) == nil ||
		func() bool {
			_, kind := Noise(c.Rel)
			return kind == "agent state" && !agentMemory(c.Rel) && !slices.Contains(c.Flags, shellStateFlag)
		}()) {
		fmt.Fprintf(w, "%s %s (agent state; contents not shown)\n", map[string]string{Added: "+", Deleted: "-", Modified: "~", Replaced: "!"}[c.Kind], display(c))
		return
	}
	// A config file is shown by the names of the keys that changed, by
	// class, never their values, which may carry tokens.
	if notes, ok := configNotes(c); ok {
		var parts []string
		for _, f := range notes {
			if f != "persist" {
				parts = append(parts, f)
			}
		}
		if len(parts) == 0 {
			parts = []string{"no key changed"}
		}
		fmt.Fprintf(w, "%s %s: %s\n", map[string]string{Added: "+", Deleted: "-", Modified: "~", Replaced: "!"}[c.Kind], display(c), strings.Join(parts, "; "))
		return
	}
	a, b := c.Path, c.Upper
	switch c.Kind {
	case Added:
		a = "/dev/null"
	case Deleted:
		b = "/dev/null"
	}
	cmd := exec.CommandContext(context.Background(), "diff", "-u", "--label", "a/"+display(c), "--label", "b/"+display(c), a, b) //nolint:gosec // each label follows --label, and a and b are absolute paths
	cmd.Stdout, cmd.Stderr = w, w
	_ = cmd.Run() // diff exits 1 when files differ
}

func fileNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// intentHasSecret: an intent runs on the host and sends what its
// command line says, so a secret value in it leaves when it runs.
func intentHasSecret(in outbox.Intent, secrets []string) bool {
	line := strings.Join(in.Argv, " ")
	if in.Request != nil && in.Request.PullRequest != nil {
		line += "\n" + in.Request.PullRequest.Title + "\n" + in.Request.PullRequest.Body
	}
	for _, v := range secrets {
		if strings.Contains(line, v) {
			return true
		}
	}
	return false
}

// renderRequests lists the requests to hosts a credential is bound to:
// airbag terminated TLS for those, so it saw each method and path.
func renderRequests(w io.Writer, effs []effects.Effect) {
	reqs, with := map[string]int{}, map[string]string{}
	for _, e := range effs {
		if e.Kind != "http.request" || e.Verdict != "allow" {
			continue
		}
		reqs[e.Target]++
		if e.Reason != "" {
			with[e.Target] = e.Reason
		}
	}
	if len(reqs) == 0 {
		return
	}
	keys := sortedKeys(reqs)
	sort.SliceStable(keys, func(i, j int) bool { return reqs[keys[i]] > reqs[keys[j]] })
	fmt.Fprintf(w, "Requests   %d to hosts with a credential\n", total(reqs))
	for i, k := range keys {
		if i == maxListed {
			fmt.Fprintf(w, "  … and %d more\n", len(keys)-maxListed)
			break
		}
		note := ""
		if c := with[k]; c != "" {
			note = "  with " + c
		}
		fmt.Fprintf(w, "  %s ×%d%s\n", k, reqs[k], note)
	}
}
