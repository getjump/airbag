// Package shim holds the commands airbag puts first in the agent's PATH.
package shim

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/getjump/airbag/internal/control"
	"github.com/getjump/airbag/outbox"
)

// BinDir is the shim directory inside the sandbox: /run/airbag/bin on
// Linux, a directory of the session on macOS (AIRBAG_SHIM_DIR).
var BinDir = binDir()

func binDir() string {
	if d := os.Getenv("AIRBAG_SHIM_DIR"); d != "" {
		return d
	}
	return "/run/airbag/bin"
}

// Git turns `git push` into an outbox intent and runs any other git
// command unchanged. Bypassing the shim does not help the agent: the
// push still has to leave through the egress proxy, which denies it.
func Git(args []string) {
	if sub, rest := subcommand(args); sub == "push" && !contains(rest, "--dry-run", "-n") {
		cwd, _ := os.Getwd()
		in, err := control.Submit(outbox.Intent{Kind: "git.push", Argv: append([]string{"git"}, args...), Cwd: cwd})
		if err != nil {
			fmt.Fprintf(os.Stderr, "airbag: could not queue git push: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "airbag: git push queued as intent %s; it runs on the host after the human approves it in `airbag review`. Do not retry.\n", in.ID)
		os.Exit(0)
	}
	real, err := lookPathSkipping("git", BinDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "airbag: git not found")
		os.Exit(127)
	}
	err = syscall.Exec(real, append([]string{"git"}, args...), os.Environ()) //nolint:gosec // the shim becomes git, inside the sandbox
	fmt.Fprintf(os.Stderr, "airbag: exec git: %v\n", err)
	os.Exit(126)
}

// subcommand skips git's global options to find the command name.
func subcommand(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-C" || a == "-c" || a == "--git-dir" || a == "--work-tree" || a == "--namespace" || a == "--exec-path":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			return a, args[i+1:]
		}
	}
	return "", nil
}

func contains(args []string, opts ...string) bool {
	for _, a := range args {
		for _, o := range opts {
			if a == o {
				return true
			}
		}
	}
	return false
}

func lookPathSkipping(name, skip string) (string, error) {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || filepath.Clean(dir) == skip {
			continue
		}
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 { //nolint:gosec // a lookup in PATH, inside the sandbox
			return p, nil
		}
	}
	return exec.LookPath("/usr/bin/" + name)
}
