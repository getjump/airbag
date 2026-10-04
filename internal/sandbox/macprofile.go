package sandbox

import (
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
// prototype has no branch of $HOME, so ~/.claude.json cannot get the
// key-level write-back the Linux path applies (agentconfig.go); it is
// left writable and persists in full, a residual noted in docs/macos.md.
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
	for _, d := range stateDirs {
		if noSymlinkSoFar(s.Home, d) == nil {
			_ = os.MkdirAll(filepath.Join(s.Home, d), 0o700)
		}
		p.Write = append(p.Write, filepath.Join(home, strings.TrimSuffix(d, "/")))
	}
	for _, f := range s.Passthrough {
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
