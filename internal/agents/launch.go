package agents

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

type Launch struct {
	ID   string
	Args []string
}

var launchers = map[string]string{"codex": "codex-yolo"}

func IsLauncher(name string) bool { _, ok := launchers[name]; return ok }

func LaunchArgs(name string, args []string) (Launch, error) {
	id, ok := launchers[name]
	if !ok {
		return Launch{}, fmt.Errorf("unknown agent launcher %q", name)
	}
	if len(args) == 0 || args[0] != "yolo" {
		return Launch{}, fmt.Errorf("usage: airbag %s yolo [airbag flags] -- [agent arguments]", name)
	}
	args = args[1:]
	at := slices.Index(args, "--")
	if at < 0 {
		at = len(args)
	}
	flags := slices.Clone(args[:at])
	for i := 0; i < len(flags); i++ {
		if flags[i] == "--execution=split" {
			id = "codex-yolo-split"
			flags = slices.Delete(flags, i, i+1)
			i--
		} else if strings.HasPrefix(flags[i], "--execution") {
			return Launch{}, errors.New("--execution only accepts --execution=split")
		}
	}
	run := flags
	run = append(run, "--", name, "--no-daemon", "--dangerously-bypass-approvals-and-sandbox")
	if !IsSplitLaunch(id) {
		run = append(run, "-c", "allow_login_shell=false")
	}
	if at < len(args) {
		run = append(run, args[at+1:]...)
	}
	return Launch{ID: id, Args: run}, nil
}

func LaunchEnv(id, state string) map[string]string {
	if id == "codex-yolo" || IsSplitLaunch(id) {
		return map[string]string{"CODEX_HOME": state}
	}
	return nil
}

func ValidateLaunch(id string, argv []string) error {
	if (id == "codex-yolo" || IsSplitLaunch(id)) && len(argv) >= 3 && argv[0] == "codex" && argv[1] == "--no-daemon" && argv[2] == "--dangerously-bypass-approvals-and-sandbox" {
		return nil
	}
	return errors.New("invalid named launcher arguments; put agent arguments after --")
}

func LaunchSource(id, home string) string {
	if id == "codex-yolo" || IsSplitLaunch(id) {
		if dir := os.Getenv("CODEX_HOME"); dir != "" {
			return dir
		}
		return filepath.Join(home, ".codex")
	}
	return ""
}

type PrepareLaunchIn struct {
	ID, Source, State string
}

func PrepareLaunch(in PrepareLaunchIn) error {
	if in.ID != "codex-yolo" && !IsSplitLaunch(in.ID) {
		return fmt.Errorf("unknown agent launcher %q", in.ID)
	}
	if fi, err := os.Lstat(in.State); err == nil {
		if !fi.IsDir() {
			return errors.New("private agent state is not a directory")
		}
		return prepareLaunchConfig(in.State)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check private agent state: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(in.Source, "auth.json"), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read file-based login (auth.json must be a regular file): %w", err)
	}
	var auth []byte
	if f != nil {
		defer func() { _ = f.Close() }()
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
			return errors.New("auth.json must be a regular file smaller than 1 MiB")
		}
		auth, err = io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil {
			return fmt.Errorf("read file-based login: %w", err)
		}
		if len(auth) > 1<<20 {
			return errors.New("auth.json exceeds 1 MiB")
		}
	}
	if err := os.Mkdir(in.State, 0o700); err != nil {
		return fmt.Errorf("create private agent state: %w", err)
	}
	if f != nil {
		if err := os.WriteFile(filepath.Join(in.State, "auth.json"), auth, 0o600); err != nil {
			return fmt.Errorf("seed private agent login: %w", err)
		}
	}
	return prepareLaunchConfig(in.State)
}

func prepareLaunchConfig(state string) error {
	path := filepath.Join(state, "config.toml")
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check private agent defaults: %w", err)
	}
	f, err := os.CreateTemp(state, ".config-")
	if err != nil {
		return fmt.Errorf("create private agent defaults: %w", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.WriteString("allow_login_shell = false\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("write private agent defaults: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync private agent defaults: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close private agent defaults: %w", err)
	}
	if err := os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("publish private agent defaults: %w", err)
	}
	return nil
}
