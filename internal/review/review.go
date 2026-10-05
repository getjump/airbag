// Package review reads a session's branch: what changed, what deserves
// the human's attention, what is waiting in the outbox.
package review

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/secretfs"
	"github.com/getjump/airbag/internal/session"
)

const (
	Added    = "added"
	Modified = "modified"
	Deleted  = "deleted"
	Replaced = "replaced" // a directory whose old contents are gone
)

type Change struct {
	Layer string // "ws" or "home"
	Rel   string // path inside the layer
	Path  string // real path on the host
	Upper string // path of the new version in the session
	Kind  string
	Type  fs.FileMode // fs.ModeDir, fs.ModeSymlink or 0 for files
	Mode  fs.FileMode
	Flags []string
	// cfg: the agent config a change is through a link, and home the
	// $HOME it is in (classify).
	cfg  *jsonConfig
	home string
	// benign: an agent config change of benign keys only (classify).
	benign bool
}

func (c Change) IsDir() bool { return c.Type == fs.ModeDir }

// Scan walks both upper layers. Whiteouts are deletions, opaque
// directories replace their lower counterpart. What is inside such a
// directory is compared with nothing, as the agent saw it: each entry
// is added, even one the same as the file it replaces, so that applying
// the directory writes all of the agent's version.
func Scan(s *session.Session) ([]Change, error) {
	if s.Clone {
		out, err := ScanTree("ws", s.Workspace, s.CloneDir())
		if err != nil {
			return nil, err
		}
		classify(s, out)
		return out, nil
	}
	var out []Change
	layers := []struct{ name, upper, lower string }{{"ws", s.WSUpper(), s.Workspace}}
	if s.OverHome {
		layers = append(layers, struct{ name, upper, lower string }{"home", s.HomeUpper(), s.Home})
	}
	for _, l := range layers {
		var replaced []string // opaque directories found so far, as paths with a trailing slash
		err := filepath.WalkDir(l.upper, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == l.upper {
				return nil
			}
			rel, _ := filepath.Rel(l.upper, p)
			c := Change{Layer: l.name, Rel: rel, Path: filepath.Join(l.lower, rel), Upper: p}
			info, err := d.Info()
			if err != nil {
				return err
			}
			c.Mode = info.Mode().Perm()
			lst, lerr := os.Lstat(c.Path)
			for _, r := range replaced {
				if strings.HasPrefix(p, r) {
					lst, lerr = nil, fs.ErrNotExist // hidden from the agent by r
				}
			}
			switch {
			case isWhiteout(info):
				c.Kind = Deleted
				if lerr == nil {
					c.Type = lst.Mode().Type()
				}
			case info.IsDir():
				c.Type = fs.ModeDir
				if isOpaque(p) && lerr == nil {
					c.Kind = Replaced
					replaced = append(replaced, p+string(filepath.Separator))
				} else if lerr != nil {
					c.Kind = Added
				} else {
					return nil // copied up only to hold changes below
				}
			case info.Mode()&fs.ModeSymlink != 0:
				c.Type = fs.ModeSymlink
				c.Kind = Added
				if lerr == nil {
					old, _ := os.Readlink(c.Path)
					cur, _ := os.Readlink(p)
					if old == cur {
						return nil
					}
					c.Kind = Modified
				}
			default:
				c.Kind = Added
				if lerr == nil {
					if lst.Mode().IsRegular() && lst.Mode().Perm() == c.Mode && sameContent(c.Path, p) {
						return nil // touched, not changed
					}
					c.Kind = Modified
				}
			}
			out = append(out, c)
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	classify(s, out)
	return out, nil
}

func isWhiteout(info fs.FileInfo) bool {
	if info.Mode()&fs.ModeCharDevice == 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Rdev == 0
}

func isOpaque(p string) bool {
	for _, attr := range []string{"user.overlay.opaque", "trusted.overlay.opaque"} {
		buf := make([]byte, 8)
		if n, err := unix.Lgetxattr(p, attr, buf); err == nil && n > 0 && buf[0] == 'y' {
			return true
		}
	}
	return false
}

func sameContent(a, b string) bool {
	fa, err := os.Open(a)
	if err != nil {
		return false
	}
	defer func() { _ = fa.Close() }()
	fb, err := os.Open(b)
	if err != nil {
		return false
	}
	defer func() { _ = fb.Close() }()
	sa, _ := fa.Stat()
	sb, _ := fb.Stat()
	if sa.Size() != sb.Size() {
		return false
	}
	ba, bb := make([]byte, 64*1024), make([]byte, 64*1024)
	for {
		na, ea := io.ReadFull(fa, ba)
		nb, _ := io.ReadFull(fb, bb)
		if na != nb || !bytes.Equal(ba[:na], bb[:nb]) {
			return false
		}
		if ea != nil {
			return true
		}
	}
}

var buildDirs = []string{"bin/", "build/", "dist/", "target/", "out/", "node_modules/", ".venv/", "vendor/"}

func classify(s *session.Session, cs []Change) {
	secrets := knownSecrets(s.Workspace)
	var aliases []homeAlias
	if s.OverHome {
		aliases = homeAliases(s.Home, []string{s.Home, s.Workspace})
	}
	// Git's own files take names only from watched paths whose real
	// place is inside .git, not from a link to the workspace or a
	// directory above it (the workspace table flags hooks and config).
	gitDir := filepath.Join(s.Workspace, ".git")
	var gitAliases []homeAlias
	for _, a := range aliases {
		if a.target == gitDir || strings.HasPrefix(a.target, gitDir+string(filepath.Separator)) {
			gitAliases = append(gitAliases, a)
		}
	}
	for i := range cs {
		c := &cs[i]
		rel := filepath.ToSlash(c.Rel)
		if c.IsDir() {
			rel += "/"
		}
		table := persistWSTable
		if c.Layer == "home" {
			table = persistHomeTable
			c.Flags = append(c.Flags, "outside workspace")
		}
		// The $HOME paths the change stands for: its own in $HOME, and
		// in either layer the watched paths whose link leads to it (a
		// dotfiles repository as the workspace, say; homeAliases).
		var names []string
		if c.Layer == "home" {
			names = append(names, rel)
		}
		lookup := aliases
		if c.Layer == "ws" && strings.HasPrefix(rel, ".git/") {
			lookup = gitAliases
		}
		for _, a := range aliasRels(lookup, c.Path) {
			if c.IsDir() {
				a += "/"
			}
			names = append(names, a)
			if cf := configFor(strings.TrimSuffix(a, "/")); cf != nil {
				c.cfg, c.home = cf, s.Home
			}
		}
		// A deletion, a replacement, or a file or link put above where a
		// watched path really is (~/dotfiles, for ~/.bashrc ->
		// ~/dotfiles/bashrc) takes that path with it or points it
		// elsewhere: it changes the path as a whole. Only a directory
		// there, new or changed, leaves the path where it is.
		if c.Kind == Deleted || c.Kind == Replaced || !c.IsDir() {
			if above := aliasesAbove(lookup, c.Path); len(above) > 0 {
				c.Flags = append(c.Flags, "persist", "holds where "+listHome(above)+" really is")
				if slices.ContainsFunc(above, func(n string) bool { return agentMemory(n) || agentMemory(n+"/memory") }) {
					c.Flags = append(c.Flags, "agent instructions")
				}
			}
		}
		persists := func(n string, t []persistence) bool {
			return (persistReason(n, t) != "" || slices.Contains(persistNames, path.Base(n))) && !strings.HasSuffix(n, ".sample")
		}
		if (persists(rel, table) || slices.ContainsFunc(names, func(n string) bool { return persists(n, persistHomeTable) })) && !slices.Contains(c.Flags, "persist") {
			c.Flags = append(c.Flags, "persist")
		}
		if len(names) > 0 {
			// A config file (~/.claude.json) is shown by its changed
			// keys, by class: "persist" only when one of them runs code
			// or changes trust, unknown keys listed plainly, and benign
			// counters with no flag, so they need no decision.
			if notes, ok := configNotes(*c); ok {
				flags := withoutBenign(notes)
				c.Flags = append(c.Flags, flags...)
				c.benign = len(flags) == 0
			}
			// A file or link in place of a directory takes what was in it
			// away, as a replacement does, though Scan says Modified.
			kind := c.Kind
			if kind == Modified && !c.IsDir() {
				kind = Replaced
			}
			if slices.ContainsFunc(names, func(n string) bool { return touchesHostShellState(s.Home, n, kind) }) {
				c.Flags = append(c.Flags, "persist", shellStateFlag)
			}
			// Project memory is loaded into later sessions; a link where a
			// directory above it is points it at whatever the link names.
			if slices.ContainsFunc(names, func(n string) bool {
				return agentMemory(n) || (kind == Deleted || kind == Replaced) && holdsMemory(c.Path, n) ||
					c.Type == fs.ModeSymlink && aboveMemory(n)
			}) {
				c.Flags = append(c.Flags, "agent instructions")
			}
		}
		if c.Kind != Deleted && c.Type == 0 && c.Mode&0o111 != 0 && !hasPrefix(rel, buildDirs) && !strings.HasPrefix(rel, ".git/") {
			c.Flags = append(c.Flags, "executable")
		}
		if c.Kind != Deleted && c.Type == 0 && len(secrets) > 0 && containsSecret(c.Upper, secrets) {
			c.Flags = append(c.Flags, "secret in diff")
		}
	}
}

func hasPrefix(rel string, patterns []string) bool {
	for _, p := range patterns {
		if rel == strings.TrimSuffix(p, "/") || strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

// knownSecrets reads values from the workspace's real secret files, the
// same ones secretfs serves (.env at any depth, keys, credentials,
// *.tfvars). A value of 8+ characters that shows up in the agent's
// changes is reported: the branch is about to put a secret into the
// repo. Values are what follows "=" or ":" on a line; a long line with
// no spaces (the body of a PEM key) counts as a whole.
func knownSecrets(ws string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.Trim(strings.TrimSpace(v), `"',;`)
		if len(v) >= 8 && !strings.ContainsAny(v, " \t") && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, rel := range secretfs.Find(ws) {
		f := filepath.Join(ws, rel)
		if st, err := os.Stat(f); err != nil || st.Size() > 1<<20 {
			continue
		}
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-----") {
				continue
			}
			if i := strings.IndexAny(line, "=:"); i >= 0 {
				add(line[i+1:])
			} else if len(line) >= 32 {
				add(line)
			}
		}
		_ = fh.Close()
	}
	return out
}

func containsSecret(path string, secrets []string) bool {
	st, err := os.Stat(path)
	if err != nil || st.Size() > 5<<20 {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, s := range secrets {
		if bytes.Contains(b, []byte(s)) {
			return true
		}
	}
	return false
}

// Attention returns the changes a human should look at, sorted.
func Attention(cs []Change) []Change {
	var out []Change
	for _, c := range cs {
		if c.IsDir() && c.Kind == Added {
			continue // the files inside carry the flags
		}
		// In $HOME, where an agent has no work of its own, what is not
		// known to be harmless needs a look too: what review folds
		// (caches, agent state, git internals) and agent config changes
		// of benign keys only are known. Matching is by where a write
		// really landed, so one made through a link (~/.bashrc into
		// ~/dotfiles) is under a name no table knows, and shows here.
		if flagged(c) || c.Layer == "home" && folded(c) == "" && !c.benign {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
