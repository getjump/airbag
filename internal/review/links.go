package review

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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
	// whole: every path inside the tree is classified as the tree is, so
	// a link from one place in it to another adds nothing. Not so for
	// the prefix of a wildcard pattern (.local/lib for its *.pth).
	type tree struct {
		rel   string
		whole bool
	}
	var watched []tree
	for _, p := range persistHomeTable {
		for _, pat := range p.patterns {
			watched = append(watched, tree{literalPrefix(pat), strings.HasSuffix(pat, "/") && !strings.Contains(pat, "*")})
		}
	}
	for _, cf := range jsonConfigs {
		watched = append(watched, tree{cf.path, false})
	}
	for _, d := range hostShellState {
		watched = append(watched, tree{strings.TrimSuffix(d.dir, "/"), true})
	}
	// Each project's directory and its memory, not the transcripts.
	if ents, err := os.ReadDir(filepath.Join(home, ".claude/projects")); err == nil {
		watched = append(watched, tree{".claude/projects", false})
		for _, e := range ents {
			watched = append(watched, tree{".claude/projects/" + e.Name(), false}, tree{".claude/projects/" + e.Name() + "/memory", true})
		}
	}
	var out []homeAlias
	seen := map[string]bool{}
	// add records where rel really is, unless that is inside within (the
	// watched tree it was found in, whose own names classify it already).
	add := func(rel, within string) {
		if rel == "" || seen[rel] {
			return
		}
		seen[rel] = true
		t, ok := resolveIn(home, rel, roots)
		// A watched name linked to a directory above itself ($HOME, say)
		// would stand for every change there: skip it. One linked to the
		// workspace root is kept: working on a config's own repository,
		// every change there is that config.
		if !ok || strings.HasPrefix(filepath.Join(home, rel), t+string(filepath.Separator)) {
			return
		}
		if within != "" && strings.HasPrefix(t, within+string(filepath.Separator)) {
			return
		}
		out = append(out, homeAlias{rel, t})
	}
	for _, tr := range watched {
		w := tr.rel
		add(w, "")
		if w == ".claude/projects" || strings.Count(w, "/") == 2 && strings.HasPrefix(w, ".claude/projects/") {
			continue // the transcripts are not watched
		}
		// The links inside, wherever the directory really is, and inside
		// a linked directory's target too, under the name it stands for.
		root, err := filepath.EvalSymlinks(filepath.Join(home, w))
		if err != nil {
			continue
		}
		n := 0
		walked := map[string]bool{}
		var walk func(dir, name string)
		walk = func(dir, name string) {
			if walked[dir] {
				return // a loop of linked directories
			}
			walked[dir] = true
			within := ""
			if tr.whole {
				within, _ = under(dir, roots)
			}
			_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil //nolint:nilerr // an unreadable entry: skip it, look at the rest
				}
				if n++; n > maxAliasEntries {
					return filepath.SkipAll
				}
				if p == dir || d.Type()&fs.ModeSymlink == 0 {
					return nil
				}
				sub, err := filepath.Rel(dir, p)
				if err != nil {
					return nil //nolint:nilerr // not below dir: nothing to name
				}
				linked := name + "/" + filepath.ToSlash(sub)
				add(linked, within)
				t, err := filepath.EvalSymlinks(p)
				if err != nil || strings.HasPrefix(t, dir+string(filepath.Separator)) {
					return nil //nolint:nilerr // dangling, or walked here anyway
				}
				if fi, err := os.Stat(t); err == nil && fi.IsDir() {
					if _, ok := under(t, roots); ok {
						walk(t, linked)
					}
				}
				return nil
			})
		}
		walk(root, w)
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
				dir := filepath.Dir(p)
				if r, err := filepath.EvalSymlinks(dir); err == nil {
					dir = r // the link's own directory, as it really is
				}
				t = filepath.Join(dir, t)
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

// under maps a real path to the most specific root it is inside (the
// workspace inside $HOME, say), as that root is written, so the result
// is spelled as the change it is found as.
func under(real string, roots []string) (string, bool) {
	best, bestLen := "", -1
	for _, root := range roots {
		rr, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		in, err := filepath.Rel(rr, real)
		if err == nil && in != ".." && !strings.HasPrefix(in, ".."+string(filepath.Separator)) && len(rr) > bestLen {
			best, bestLen = filepath.Join(root, in), len(rr)
		}
	}
	return best, bestLen >= 0
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
