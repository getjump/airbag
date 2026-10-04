package review

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/steps"
)

// Noise: caches in $HOME are folded into one line per directory.
var homeNoise = []string{".cache/", ".npm/", "go/pkg/", ".cargo/registry/", ".local/share/", ".local/state/", ".rustup/"}

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
		folded := map[string]int{}
		var shown []Change
		for _, c := range home {
			if dir := NoiseDir(c.Rel); dir != "" && !flagged(c) {
				folded[dir+"… (cache)"]++
				continue
			}
			if repo := GitDir(c.Rel); repo != "" && !flagged(c) {
				folded[repo+"… (git internals)"]++
				continue
			}
			shown = append(shown, c)
		}
		list(w, shown, "~/")
		for _, dir := range sortedKeys(folded) {
			fmt.Fprintf(w, "  · ~/%s %d files\n", dir, folded[dir])
		}
	}

	allowed, denied := map[string]int{}, map[string]int{}
	for _, e := range effs {
		if e.Kind != "net.egress" {
			continue
		}
		host, _, err := net.SplitHostPort(e.Target)
		if err != nil {
			host = e.Target
		}
		if e.Verdict == "deny" {
			denied[e.Target]++
		} else {
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
		fmt.Fprintf(w, "\nSecrets    read: %s\n           egress was limited to model APIs and registries from then on\n", strings.Join(reads, ", "))
	}
	fmt.Fprintf(w, "\nNetwork    %d allowed%s\n", total(allowed), hostList(allowed))
	if len(denied) > 0 {
		fmt.Fprintf(w, "           %d denied%s\n", total(denied), hostList(denied))
	}

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

	fmt.Fprintf(w, "\nOutbox     %d\n", len(intents))
	for _, in := range intents {
		fmt.Fprintf(w, "  %-4s %-44s %s\n", in.ID, strings.Join(in.Argv, " "), in.Status)
	}

	if att := Attention(cs); len(att) > 0 {
		fmt.Fprintf(w, "\nAttention\n")
		for _, c := range att {
			fmt.Fprintf(w, "  ! %-40s %s\n", display(c), strings.Join(c.Flags, ", "))
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
		flags := ""
		if f := withoutOutside(c.Flags); len(f) > 0 {
			flags = "  " + strings.Join(f, ", ")
		}
		fmt.Fprintf(w, "  %s %s%s\n", mark, name, flags)
	}
}

func display(c Change) string {
	if c.Layer == "home" {
		return "~/" + c.Rel
	}
	return c.Rel
}

func flagged(c Change) bool { return len(withoutOutside(c.Flags)) > 0 }

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

func NoiseDir(rel string) string {
	for _, p := range homeNoise {
		if strings.HasPrefix(rel+"/", p) {
			return p
		}
	}
	return ""
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
		for _, c := range st.Changes {
			mark, rest := c[:1], c[1:]
			layer, path, _ := strings.Cut(rest, ":")
			if GitDir(path) != "" {
				git++
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
	a, b := c.Path, c.Upper
	switch c.Kind {
	case Added:
		a = "/dev/null"
	case Deleted:
		b = "/dev/null"
	}
	cmd := exec.Command("diff", "-u", "--label", "a/"+display(c), "--label", "b/"+display(c), a, b)
	cmd.Stdout, cmd.Stderr = w, w
	_ = cmd.Run() // diff exits 1 when files differ
}
