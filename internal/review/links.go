package review

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// A dotfiles manager keeps ~/.bashrc, ~/.claude or ~/.config/nvim as a
// symlink into a directory of its own (~/dotfiles/bashrc), often the
// repository the agent works in. The agent's write through such a link,
// or straight to the file in that repository, lands on the link's
// target, so the change is found under the target's path, which no table
// names. homeAliases finds, once per scan, where each path review
// watches really is; a change at a target is then also classified under
// the watched name it stands for.

// homeAlias says that the watched path link (relative to $HOME, slash
// separated) is really target (a real path inside $HOME or the
// workspace, the trees the agent can write).
type homeAlias struct{ link, target string }

// maxAliasEntries bounds how many entries below one watched directory
// are looked at for links of their own; a link deeper in a tree larger
// than that is not followed.
const maxAliasEntries = 5000

// homeAliases returns the watched paths that resolve elsewhere inside
// one of roots (home and the workspace): every persistence path, the
// agent configs, the shell state the agent's CLI sources and each
// project's memory, with any link among their ancestors followed, and
// every link inside a watched directory, which a dotfiles manager may
// make file by file at any depth.
func homeAliases(home string, roots []string) []homeAlias {
	var watched []string
	for _, p := range persistHomeTable {
		for _, pat := range p.patterns {
			watched = append(watched, literalPrefix(pat))
		}
	}
	for _, cf := range jsonConfigs {
		watched = append(watched, cf.path)
	}
	for _, d := range hostShellState {
		watched = append(watched, strings.TrimSuffix(d.dir, "/"))
	}
	// Each project's directory and its memory, not the transcripts.
	if ents, err := os.ReadDir(filepath.Join(home, ".claude/projects")); err == nil {
		watched = append(watched, ".claude/projects")
		for _, e := range ents {
			watched = append(watched, ".claude/projects/"+e.Name(), ".claude/projects/"+e.Name()+"/memory")
		}
	}
	var out []homeAlias
	seen := map[string]bool{}
	add := func(rel string) {
		if rel == "" || seen[rel] {
			return
		}
		seen[rel] = true
		t, ok := resolveIn(home, rel, roots)
		// A watched name linked to a whole tree, or to a directory
		// above itself, would stand for every change in it: skip it.
		if !ok || slices.Contains(roots, t) || strings.HasPrefix(filepath.Join(home, rel), t+string(filepath.Separator)) {
			return
		}
		out = append(out, homeAlias{rel, t})
	}
	for _, w := range watched {
		add(w)
		if w == ".claude/projects" || strings.Count(w, "/") == 2 && strings.HasPrefix(w, ".claude/projects/") {
			continue // the transcripts are not watched
		}
		// The links inside, wherever the directory really is.
		root, err := filepath.EvalSymlinks(filepath.Join(home, w))
		if err != nil {
			continue
		}
		n := 0
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // an unreadable entry: skip it, look at the rest
			}
			if n++; n > maxAliasEntries {
				return filepath.SkipAll
			}
			if p != root && d.Type()&fs.ModeSymlink != 0 {
				if sub, err := filepath.Rel(root, p); err == nil {
					add(w + "/" + filepath.ToSlash(sub))
				}
			}
			return nil
		})
	}
	return out
}

// literalPrefix is the part of a table pattern before any wildcard, as a
// path without a trailing slash.
func literalPrefix(pat string) string {
	if i := strings.Index(pat, "*"); i >= 0 {
		pat = pat[:i]
		if j := strings.LastIndex(pat, "/"); j >= 0 {
			pat = pat[:j]
		} else {
			pat = ""
		}
	}
	return strings.TrimSuffix(pat, "/")
}

// maxHops bounds the dangling links resolveIn follows, against a loop.
const maxHops = 40

// resolveInHome is resolveIn with home as the only root.
func resolveInHome(home, rel string) (string, bool) { return resolveIn(home, rel, []string{home}) }

// resolveIn returns where home/rel really is, with every symlink on the
// way followed, as a path under the first of roots it is inside (as that
// root is written), and whether it is inside one and somewhere else than
// home/rel. Outside every root is read-only to the agent. A part of the
// path that does not exist yet is joined on as written, so a new file
// below a linked directory resolves too, and a link to something that
// does not exist yet is followed by what it says.
func resolveIn(home, rel string, roots []string) (string, bool) {
	p, rest := filepath.Join(home, rel), ""
	for hops := 0; hops <= maxHops; {
		r, err := filepath.EvalSymlinks(p)
		if err == nil {
			t, ok := under(filepath.Join(r, rest), roots)
			return t, ok && t != filepath.Join(home, rel)
		}
		if fi, lerr := os.Lstat(p); lerr == nil && fi.Mode()&fs.ModeSymlink != 0 && errors.Is(err, fs.ErrNotExist) {
			t, err := os.Readlink(p)
			if err != nil {
				return "", false
			}
			if !filepath.IsAbs(t) {
				t = filepath.Join(filepath.Dir(p), t)
			}
			p, rest = filepath.Join(t, rest), ""
			hops++
			continue
		}
		if p == home || p == filepath.Dir(p) {
			return "", false
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = filepath.Dir(p)
	}
	return "", false
}

// under maps a real path to the root it is inside, as the root is
// written.
func under(real string, roots []string) (string, bool) {
	for _, root := range roots {
		rr, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		in, err := filepath.Rel(rr, real)
		if err == nil && in != ".." && !strings.HasPrefix(in, ".."+string(filepath.Separator)) {
			return filepath.Join(root, in), true
		}
	}
	return "", false
}

// aliasRels returns the watched names a change at real path p stands
// for, relative to $HOME and slash separated.
func aliasRels(aliases []homeAlias, p string) []string {
	var out []string
	for _, a := range aliases {
		switch {
		case p == a.target:
			out = append(out, a.link)
		case strings.HasPrefix(p, a.target+string(filepath.Separator)):
			out = append(out, a.link+filepath.ToSlash(p[len(a.target):]))
		}
	}
	return out
}
