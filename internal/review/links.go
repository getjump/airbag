package review

import (
	"os"
	"path/filepath"
	"strings"
)

// A dotfiles manager keeps ~/.bashrc, ~/.claude or ~/.config/nvim as a
// symlink into a directory of its own inside $HOME (~/dotfiles/bashrc).
// The agent's write through such a link lands on the link's target, so
// the change is found under the target's path, which no table names.
// homeAliases finds, once per scan, where each path review watches
// really is; a change at a target is then also classified under the
// watched name it stands for.

// homeAlias says that the watched path link (relative to $HOME, slash
// separated) is really target (a real path inside $HOME).
type homeAlias struct{ link, target string }

// maxAliasEntries bounds how many entries of a watched directory are
// checked for links of their own.
const maxAliasEntries = 256

// homeAliases returns the watched paths that resolve elsewhere inside
// home: every persistence path, the agent configs and the shell state
// the agent's CLI sources, with any link among their ancestors followed,
// and the direct entries of the watched directories, which a dotfiles
// manager may link one by one.
func homeAliases(home string) []homeAlias {
	var watched []string
	for _, p := range persistHomeTable {
		for _, pat := range p.patterns {
			watched = append(watched, literalPrefix(pat))
		}
	}
	for _, cf := range jsonConfigs {
		watched = append(watched, cf.path)
	}
	watched = append(watched, ".claude/projects")
	for _, d := range hostShellState {
		watched = append(watched, strings.TrimSuffix(d.dir, "/"))
	}
	var out []homeAlias
	seen := map[string]bool{}
	add := func(rel string) {
		if rel == "" || seen[rel] {
			return
		}
		seen[rel] = true
		if t, ok := resolveInHome(home, rel); ok {
			out = append(out, homeAlias{rel, t})
		}
	}
	for _, w := range watched {
		add(w)
		ents, err := os.ReadDir(filepath.Join(home, w))
		if err != nil {
			continue
		}
		for i, e := range ents {
			if i == maxAliasEntries {
				break
			}
			if e.Type()&os.ModeSymlink != 0 {
				add(w + "/" + e.Name())
			}
		}
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

// resolveInHome returns where home/rel really is, with every symlink on
// the way followed, as a path under home as written, and whether that is
// inside home and somewhere else than home/rel. A part of the path that
// does not exist yet is joined on as written, so a new file below a
// linked directory resolves too.
func resolveInHome(home, rel string) (string, bool) {
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return "", false
	}
	p, rest := filepath.Join(home, rel), ""
	for {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			in, err := filepath.Rel(realHome, filepath.Join(r, rest))
			if err != nil || in == ".." || strings.HasPrefix(in, ".."+string(filepath.Separator)) {
				return "", false // outside home: read-only to the agent
			}
			t := filepath.Join(home, in)
			return t, t != filepath.Join(home, rel)
		}
		if p == home || p == filepath.Dir(p) {
			return "", false
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = filepath.Dir(p)
	}
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
