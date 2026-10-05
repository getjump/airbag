package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/getjump/airbag/internal/seatbelt"
	"github.com/getjump/airbag/internal/secretfs"
	"github.com/getjump/airbag/internal/session"
)

// The Seatbelt profile of the macOS prototype (run_darwin.go). It is
// plain data, so it is built and tested on any platform.

// stateDirs: agent state the profile lets the agent write in $HOME,
// besides the session's Passthrough. Settings, hooks and instructions
// inside them stay read-only (stateReadOnly): without a branch of $HOME
// those would persist outside review.
var stateDirs = []string{".claude/", ".codex/"}

// macStateWriteFiles: single files in $HOME the agent may write on
// macOS although they go through the branch on Linux. The macOS
// prototype has no branch of $HOME, so ~/.claude.json cannot go through
// the branch and the key-level review the Linux path gives it
// (agentconfig.go); it is left writable and persists in full, a residual
// noted in docs/macos.md.
var macStateWriteFiles = []string{".claude.json"}

var stateReadOnly = []string{
	".claude/settings.json", ".claude/settings.local.json", ".claude/hooks", ".claude/agents",
	".claude/skills", ".claude/commands", ".claude/plugins", ".claude/CLAUDE.md",
	".claude/rules", ".claude/output-styles", ".claude/workflows", ".claude/agent-memory",
	".claude/remote-settings.json",
	".codex/config.toml", ".codex/hooks.json", ".codex/rules", ".codex/AGENTS.md",
}

func macProfile(s *session.Session, port int, tmp, cache string) (seatbelt.Profile, error) {
	real := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	home := real(s.Home)
	clone := real(s.CloneDir())
	p := seatbelt.Profile{
		Tag:     "airbag-" + s.ID,
		Write:   []string{clone, real(tmp), real(cache)},
		Ports:   []int{port},
		Sockets: []string{real(s.ControlSock())},
	}
	// tcp:// forwards to this machine: on macOS the agent reaches them
	// directly, the profile only has to let it.
	for _, f := range s.Forwards {
		if f.Host == "localhost" || f.Host == "127.0.0.1" || f.Host == "::1" {
			p.Ports = append(p.Ports, f.Port)
		}
	}
	// A protected file (memory, settings, hooks) with another name in a
	// state directory would be written through that name, which a deny
	// on its path does not cover: then no state directory is writable.
	linked, unchecked := protectedLinks(s.Home)
	switch {
	case linked != "":
		fmt.Fprintf(os.Stderr, "airbag: warning: ~/.claude and ~/.codex stay read-only: %s has another hard link (find it with find ~ -samefile, and make one of them a copy or a symlink)\n", linked)
	case unchecked != "":
		fmt.Fprintf(os.Stderr, "airbag: warning: ~/.claude and ~/.codex stay read-only: %s could not be checked in full for hard links (unreadable, or more than %d files)\n", unchecked, maxPassFiles)
	}
	for _, d := range stateDirs {
		if noSymlinkSoFar(s.Home, d) == nil {
			_ = os.MkdirAll(filepath.Join(s.Home, d), 0o700)
		}
		if linked == "" && unchecked == "" {
			p.Write = append(p.Write, filepath.Join(home, strings.TrimSuffix(d, "/")))
		}
	}
	for _, f := range s.Passthrough {
		// Seatbelt rules match paths, so a file there with another name
		// elsewhere would be written through this one: each is denied
		// (the state directories around it are writable as a whole).
		linked, full := hardLinks(s.Home, strings.TrimSuffix(f, "/"))
		for _, l := range linked {
			fmt.Fprintf(os.Stderr, "airbag: warning: ~/%s stays read-only (it has another hard link)\n", l)
			p.NoWrite = append(p.NoWrite, filepath.Join(home, l))
		}
		if !full {
			// One not looked at may have another name: none is writable.
			fmt.Fprintf(os.Stderr, "airbag: warning: ~/%s stays read-only (it could not be checked in full for hard links)\n", f)
			p.NoWrite = append(p.NoWrite, filepath.Join(home, strings.TrimSuffix(f, "/")))
			continue
		}
		if strings.HasSuffix(f, "/") {
			p.Write = append(p.Write, filepath.Join(home, strings.TrimSuffix(f, "/")))
		} else {
			p.WriteFiles = append(p.WriteFiles, filepath.Join(home, f))
		}
	}
	for _, f := range macStateWriteFiles {
		p.WriteFiles = append(p.WriteFiles, filepath.Join(home, f))
	}
	for _, f := range stateReadOnly {
		p.NoWrite = append(p.NoWrite, filepath.Join(home, f))
		// Seatbelt checks the path a write resolves to: a read-only path
		// that is a link is denied where it really is too, with the
		// directories above that place.
		if r := follow(filepath.Join(s.Home, f)); r != filepath.Join(home, f) {
			p.NoWrite = append(p.NoWrite, r)
			for d := filepath.Dir(r); d != home && d != filepath.Dir(d); d = filepath.Dir(d) {
				p.NoWriteRegex = append(p.NoWriteRegex, "^"+regexp.QuoteMeta(d)+"$")
			}
		}
	}
	// A branch hole cannot be served from a branch on macOS (there is
	// none), so the profile denies writing it instead: memory/ edits are
	// blocked rather than silently persisted unreviewed (docs/macos.md).
	for _, h := range s.BranchHoles {
		p.NoWrite = append(p.NoWrite, filepath.Join(home, h))
	}
	// Every project's memory/, not only this workspace's: they are all
	// loaded into later sessions of their project. A deny on a path does
	// not cover renaming one of its ancestors, so the directories above
	// the denied ones cannot be created, removed or renamed either: the
	// state roots, projects/ and each project directory. This workspace's
	// project directory and its memory/ are made before the run, since
	// the agent cannot create them.
	q := regexp.QuoteMeta(home)
	p.NoWriteRegex = append(p.NoWriteRegex,
		"^"+q+`/\.claude/projects/[^/]+/memory(/|$)`,
		"^"+q+`/\.(claude|codex)$`,
		"^"+q+`/\.claude/projects(/[^/]+)?$`)
	// Seatbelt checks the path a write resolves to: a memory/ that is,
	// or lies under, a link elsewhere is denied where it really is, with
	// the directories above it as above.
	// So may ~/.claude/projects itself: the patterns above apply where it
	// really is too, for projects made later.
	if r := follow(filepath.Join(s.Home, ".claude/projects")); r != filepath.Join(home, ".claude/projects") {
		q := regexp.QuoteMeta(r)
		p.NoWriteRegex = append(p.NoWriteRegex, "^"+q+`/[^/]+/memory(/|$)`, "^"+q+`(/[^/]+)?$`)
		for d := filepath.Dir(r); d != home && d != filepath.Dir(d); d = filepath.Dir(d) {
			p.NoWriteRegex = append(p.NoWriteRegex, "^"+regexp.QuoteMeta(d)+"$")
		}
	}
	for _, m := range realMemory(s.Home) {
		p.NoWrite = append(p.NoWrite, m)
		for d := filepath.Dir(m); d != home && d != filepath.Dir(d); d = filepath.Dir(d) {
			p.NoWriteRegex = append(p.NoWriteRegex, "^"+regexp.QuoteMeta(d)+"$")
		}
	}
	for _, h := range s.BranchHoles {
		if noSymlinkSoFar(s.Home, h) == nil { // MkdirAll would follow a symlink out of $HOME
			_ = os.MkdirAll(filepath.Join(s.Home, h), 0o700)
		}
	}
	for _, h := range s.Hidden {
		p.NoRead = append(p.NoRead, filepath.Join(home, h))
	}
	for _, h := range MacHidden {
		p.NoRead = append(p.NoRead, filepath.Join(home, h))
	}
	p.NoRead = append(p.NoRead, s.HiddenHost...)
	// Without FUSE a read of a secret file cannot be tracked, so the
	// agent cannot read one, in the clone or in the real workspace.
	ws := real(s.Workspace)
	for _, rel := range secretfs.Find(s.Workspace) {
		p.NoRead = append(p.NoRead, filepath.Join(clone, rel), filepath.Join(ws, rel))
	}
	return p, nil
}

// realMemory returns where each project's memory/ really is, when a
// link leads there: the project directory or memory/ itself may be one.
// A link to a place that does not exist yet gives that place, which
// the agent could otherwise create.
func realMemory(home string) []string {
	root := filepath.Join(home, ".claude/projects")
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if m := follow(filepath.Join(follow(filepath.Join(root, e.Name())), "memory")); m != filepath.Join(root, e.Name(), "memory") {
			out = append(out, m)
		}
	}
	return out
}

// follow returns where p leads, with the links on the way followed: the
// last one by what it says, though nothing may be there yet.
func follow(p string) string {
	for range maxMemoryHops {
		if d, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
			p = filepath.Join(d, filepath.Base(p))
		}
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			return p
		}
		t, err := os.Readlink(p)
		if err != nil {
			return p
		}
		if !filepath.IsAbs(t) {
			t = filepath.Join(filepath.Dir(p), t)
		}
		p = t
	}
	return p
}

// maxMemoryHops bounds the links follow follows, against a loop.
const maxMemoryHops = 40

// protectedLinks returns the first file the profile protects in the
// state directories (every project's memory, the read-only state) that
// has more than one name, or else the first path it could not check in
// full. A protected path that is a link (a dotfiles hooks/) is checked
// where it leads as well: a walk does not follow the link it starts at.
func protectedLinks(home string) (linked, unchecked string) {
	paths := append([]string(nil), stateReadOnly...)
	projects := filepath.Join(home, ".claude/projects")
	ents, err := os.ReadDir(projects)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", projects
	}
	for _, e := range ents {
		// A file there (a .DS_Store) holds no memory.
		if e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
			paths = append(paths, ".claude/projects/"+e.Name()+"/memory")
		}
	}
	for _, p := range paths {
		at := filepath.Join(home, p)
		roots := []string{at}
		if r := follow(at); r != at {
			roots = append(roots, r)
		}
		for _, r := range roots {
			l, full := hardLinks(filepath.Dir(r), filepath.Base(r))
			if len(l) > 0 {
				return filepath.Join(filepath.Dir(r), l[0]), ""
			}
			if !full {
				return "", r
			}
		}
	}
	return "", ""
}
