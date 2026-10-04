package review

import (
	"path"
	"strings"
)

// Persistence: places where a file makes code run later, outside the
// sandbox, or changes where code comes from. A change to one of them is
// flagged "persist" in review and never folded into noise.
//
// Sources: PANIX (github.com/Aegrah/PANIX, user-level Linux persistence
// techniques), MITRE ATT&CK T1546 (event triggered execution), T1547
// (boot or logon autostart), T1543 (systemd services), T1574 (hijack
// execution flow), systemd.unit(5) user unit search paths, the XDG
// autostart and D-Bus activation specs, and each tool's documentation.
//
// A pattern ending in "/" matches a directory and everything below it;
// a pattern with * is matched with path.Match against the whole path;
// any other pattern matches that exact path.
type persistence struct {
	why      string
	patterns []string
}

var persistHomeTable = []persistence{
	{"shell startup", []string{
		".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
		".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".config/fish/",
		".kshrc", ".mkshrc", ".cshrc", ".tcshrc", ".login", ".logout",
		".oh-my-zsh/custom/", ".local/share/bash-completion/", ".inputrc",
	}},
	{"session environment", []string{".config/environment.d/", ".pam_environment", ".xprofile", ".xinitrc", ".xsession", ".xsessionrc"}},
	{"systemd user units", []string{".config/systemd/", ".local/share/systemd/"}},
	{"autostart and activation", []string{
		".config/autostart/", ".config/autostart-scripts/", ".config/plasma-workspace/",
		".local/share/applications/", ".config/mimeapps.list", ".local/share/dbus-1/",
	}},
	{"window manager startup", []string{".config/i3/", ".config/sway/", ".config/hypr/", ".config/niri/"}},
	{"commands on PATH", []string{".local/bin/", "bin/", ".bin/", "go/bin/", ".cargo/bin/", ".deno/bin/", ".bun/bin/"}},
	{"code run at interpreter start", []string{
		".local/lib/python*/site-packages/*.pth", ".local/lib/python*/site-packages/usercustomize.py",
		".irbrc", ".pryrc", ".gemrc",
	}},
	{"editor and terminal config that runs code", []string{
		".vimrc", ".vim/", ".config/nvim/", ".emacs", ".emacs.d/", ".config/emacs/",
		".tmux.conf", ".config/tmux/", ".wezterm.lua", ".config/wezterm/", ".config/kitty/",
		".config/direnv/",
	}},
	{"git", []string{".gitconfig", ".config/git/"}},
	{"build tool and package source config", []string{
		".npmrc", ".yarnrc", ".yarnrc.yml", ".pypirc", ".config/pip/", ".pip/",
		".cargo/config", ".cargo/config.toml", ".config/go/", ".m2/settings.xml",
		".gradle/init.d/", ".gradle/init.gradle", ".gradle/gradle.properties",
	}},
	{"credential helpers that run commands", []string{".docker/", ".kube/", ".aws/config", ".config/gh/", ".ssh/"}},
	// ~/.claude.json is handled by agentconfig.go, not here: a change is
	// flagged "persist" only when it touches a key that runs code or
	// changes trust, so routine counter rewrites do not alarm.
	{"agent settings, hooks and instructions", []string{
		".claude/settings.json", ".claude/settings.local.json", ".claude/hooks/", ".claude/agents/",
		".claude/skills/", ".claude/commands/", ".claude/plugins/", ".claude/CLAUDE.md",
		".claude/rules/", ".claude/output-styles/", ".claude/workflows/", ".claude/agent-memory/",
		// The cache of server-managed settings, applied at startup.
		".claude/remote-settings.json",
		".codex/config.toml", ".codex/hooks.json", ".codex/rules/", ".codex/AGENTS.md",
		".gemini/", ".cursor/", ".config/airbag/",
	}},
}

var persistWSTable = []persistence{
	{"git hooks and config", []string{".git/hooks/", ".git/config", ".gitmodules", ".husky/", ".pre-commit-config.yaml", "lefthook.yml", ".lefthook.yml"}},
	{"CI", []string{".github/workflows/", ".gitlab-ci.yml"}},
	{"environment and tool config that runs code", []string{
		".envrc", ".mise.toml", "mise.toml", ".npmrc", ".yarnrc.yml", ".pnpmfile.cjs",
		".cargo/", ".mvn/", "gradle/wrapper/gradle-wrapper.properties",
	}},
	{"editor and container config", []string{".vscode/settings.json", ".vscode/tasks.json", ".vscode/launch.json", ".idea/", ".devcontainer/"}},
	{"agent settings and instructions", []string{
		".claude/", ".mcp.json", ".codex/", ".cursor/", ".gemini/", ".github/copilot-instructions.md", "airbag.yaml",
	}},
}

// Instructions agents read at the start of every later session, at any
// depth of the tree: changing them steers the next agent.
var persistNames = []string{
	"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md", "GEMINI.md",
	".cursorrules", ".windsurfrules",
}

// persistReason returns why rel (slash-separated, a directory with a
// trailing "/") is a persistence location, or "".
func persistReason(rel string, table []persistence) string {
	for _, p := range table {
		for _, pat := range p.patterns {
			if matchPersist(rel, pat) {
				return p.why
			}
		}
	}
	return ""
}

func matchPersist(rel, pat string) bool {
	switch {
	case strings.Contains(pat, "*"):
		ok, _ := path.Match(pat, strings.TrimSuffix(rel, "/"))
		return ok
	case strings.HasSuffix(pat, "/"):
		return rel == strings.TrimSuffix(pat, "/") || rel == pat || strings.HasPrefix(rel, pat)
	default:
		return strings.TrimSuffix(rel, "/") == pat
	}
}
