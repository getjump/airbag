package sandbox

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/getjump/airbag/internal/seatbelt"
	"github.com/getjump/airbag/internal/secretfs"
	"github.com/getjump/airbag/internal/session"
)

// The Seatbelt profile of the macOS prototype (run_darwin.go). It is
// plain data, so it is built and tested on any platform.

// stateDirs: agent state the profile lets the agent write in $HOME,
// besides DefaultPassthrough. Settings, hooks and instructions inside
// them stay read-only (stateReadOnly): without a branch of $HOME those
// would persist outside review.
var stateDirs = []string{".claude/", ".codex/"}

var stateReadOnly = []string{
	".claude/settings.json", ".claude/settings.local.json", ".claude/hooks", ".claude/agents",
	".claude/skills", ".claude/commands", ".claude/plugins", ".claude/CLAUDE.md",
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
	for _, d := range stateDirs {
		_ = os.MkdirAll(filepath.Join(s.Home, d), 0o700)
		p.Write = append(p.Write, filepath.Join(home, strings.TrimSuffix(d, "/")))
	}
	for _, f := range DefaultPassthrough {
		if strings.HasSuffix(f, "/") {
			p.Write = append(p.Write, filepath.Join(home, strings.TrimSuffix(f, "/")))
		} else {
			p.WriteFiles = append(p.WriteFiles, filepath.Join(home, f))
		}
	}
	for _, f := range stateReadOnly {
		p.NoWrite = append(p.NoWrite, filepath.Join(home, f))
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
