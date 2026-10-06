package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/secretfs"
	"github.com/getjump/airbag/internal/session"
)

const GuestArg = "__airbag_guest"

// PreflightRuntime runs before Create/Resume. An unavailable provider or
// unsupported policy requirement never changes the session or falls back.
func PreflightRuntime(b Backend, c session.RuntimeConfig, workspace string, overHome, nix bool, forwards int, p *policy.Policy) (session.RuntimeConfig, error) {
	if b.Name == "native" {
		if c != (session.RuntimeConfig{}) {
			return c, fmt.Errorf("runtime artifacts require an optional backend")
		}
		return c, nil
	}
	if runtime.GOOS != "linux" {
		return c, fmt.Errorf("optional runtimes require Linux")
	}
	if overHome {
		return c, fmt.Errorf("%s requires --no-home: this profile uses a private empty HOME", b.Name)
	}
	if nix || forwards != 0 || len(p.Hide) != 0 {
		return c, fmt.Errorf("%s does not support Nix daemon, TCP forwards or explicit hide rules", b.Name)
	}
	// The checks see the directory the workspace names, as the copy does
	// (exportWorkspace): through a symlink, Find would not descend and
	// would pass a workspace that holds secret files.
	workspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return c, err
	}
	if files := secretfs.Find(workspace); len(files) != 0 {
		return c, fmt.Errorf("%s cannot mediate workspace secret reads yet (%s); use native", b.Name, files[0])
	}
	if c.RootFS == "" || c.Binary == "" {
		return c, fmt.Errorf("%s requires --runtime-rootfs and --runtime-bin", b.Name)
	}
	for _, path := range []*string{&c.RootFS, &c.Binary, &c.Kernel} {
		if *path == "" {
			continue
		}
		abs, err := filepath.Abs(*path)
		if err != nil {
			return c, err
		}
		*path, err = filepath.EvalSymlinks(abs)
		if err != nil {
			return c, err
		}
	}
	st, err := os.Stat(c.RootFS)
	if err != nil {
		return c, err
	}
	if !st.IsDir() || c.RootFS == "/" {
		return c, fmt.Errorf("runtime rootfs must be a dedicated trusted directory")
	}
	// The copy is made below the sessions from the workspace: either one
	// inside the other (AIRBAG_HOME a link into the project, say), as the
	// directories they name, and the copy would copy itself.
	sessions, err := filepath.Abs(session.Root())
	if err != nil {
		return c, err
	}
	if sessions = follow(sessions); pathWithin(sessions, workspace) || pathWithin(workspace, sessions) {
		return c, fmt.Errorf("the sessions (%s) and the workspace %s lie one inside the other; set AIRBAG_HOME outside the workspace", sessions, workspace)
	}
	for _, path := range []string{workspace, session.Root()} {
		abs, err := filepath.Abs(path)
		if err != nil {
			return c, err
		}
		abs = follow(abs) // the session root may not exist yet
		if pathWithin(abs, c.RootFS) || pathWithin(c.RootFS, abs) {
			return c, fmt.Errorf("runtime rootfs must be separate from workspace and sessions")
		}
		// What runs or boots on this machine does not come from where
		// the agent's files are.
		for _, f := range []string{c.Binary, c.Kernel} {
			if f != "" && pathWithin(f, abs) {
				return c, fmt.Errorf("%s is inside the workspace or the sessions; the runtime binary and kernel must come from outside them", f)
			}
		}
	}
	st, err = os.Stat(c.Binary)
	if err != nil {
		return c, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return c, fmt.Errorf("runtime binary must be an executable regular file")
	}
	// runsc runs the sidecars in gvisor-bin next to it on the host, as
	// the user: none of them may come from where the agent's files are.
	if b.Name == "gvisor" {
		var roots []string
		for _, path := range []string{workspace, session.Root()} {
			abs, err := filepath.Abs(path)
			if err != nil {
				return c, err
			}
			roots = append(roots, follow(abs))
		}
		if err := outsideTrees(filepath.Join(filepath.Dir(c.Binary), "gvisor-bin"), roots, 0); err != nil {
			return c, err
		}
	}
	if b.Name == "microvm" {
		if runtime.GOARCH != "amd64" {
			return c, fmt.Errorf("microVM adapter currently requires Linux amd64")
		}
		if c.Kernel == "" {
			return c, fmt.Errorf("microvm requires --runtime-kernel")
		}
		st, err = os.Stat(c.Kernel)
		if err != nil {
			return c, err
		}
		if !st.Mode().IsRegular() {
			return c, fmt.Errorf("kernel must be a regular file")
		}
		f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
		if err != nil {
			return c, fmt.Errorf("microvm needs writable /dev/kvm: %w", err)
		}
		_ = f.Close()
	} else if c.Kernel != "" {
		return c, fmt.Errorf("gvisor does not use --runtime-kernel")
	}
	if err := optionalHostReady(b.Name, workspace); err != nil {
		return c, err
	}
	return c, nil
}

// hostTool finds name on PATH as a program of this machine: its path
// absolute with links resolved, and outside the workspace and the
// sessions, where the agent's files are. A PATH entry into the project,
// as direnv adds, would otherwise run the project's program on the host.
func hostTool(name, workspace string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	if p, err = filepath.Abs(p); err != nil {
		return "", err
	}
	if p, err = filepath.EvalSymlinks(p); err != nil {
		return "", err
	}
	for _, root := range []string{workspace, session.Root()} {
		if pathWithin(p, follow(root)) {
			return "", fmt.Errorf("%s on PATH is %s, inside the workspace or the sessions; put the system's first on PATH", name, p)
		}
	}
	return p, nil
}

// outsideTrees refuses p, and every file below it or a link in it leads
// to, when one lies inside roots. A p that is not there passes: runsc then
// has no sidecars to run.
func outsideTrees(p string, roots []string, depth int) error {
	if depth > 8 {
		return fmt.Errorf("%s: too many links to follow", p)
	}
	real, err := filepath.EvalSymlinks(p)
	if depth == 0 && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, root := range roots {
		if pathWithin(real, root) {
			return fmt.Errorf("%s is %s, inside the workspace or the sessions; the runtime's sidecars must come from outside them", p, real)
		}
	}
	return filepath.WalkDir(real, func(q string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// lstat each entry rather than trust the type readdir gives: on
		// a filesystem that gives none, a link would pass for a file.
		fi, err := os.Lstat(q)
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return outsideTrees(q, roots, depth+1)
		}
		return nil
	})
}

func pathWithin(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
