package agents

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLaunchArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
		fail bool
	}{
		{"default", []string{"yolo"}, []string{"--", "codex", "--no-daemon", "--dangerously-bypass-approvals-and-sandbox"}, false},
		{"arguments", []string{"yolo", "--session", "last", "--allow-trustd=false", "--", "resume", "--last", "-m", "model"}, []string{"--session", "last", "--allow-trustd=false", "--", "codex", "--no-daemon", "--dangerously-bypass-approvals-and-sandbox", "resume", "--last", "-m", "model"}, false},
		{"missing mode", nil, nil, true},
		{"unknown mode", []string{"full"}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LaunchArgs("codex", tc.args)
			if (err != nil) != tc.fail || !reflect.DeepEqual(got.Args, tc.want) {
				t.Fatalf("LaunchArgs(%q) = %v, %v; want %v, error=%v", tc.args, got.Args, err, tc.want, tc.fail)
			}
		})
	}
}

func TestValidateLaunch(t *testing.T) {
	for _, argv := range [][]string{nil, {"/usr/bin/true", "--", "codex"}, {"codex", "--no-daemon"}} {
		if err := ValidateLaunch("codex-yolo", argv); err == nil {
			t.Fatalf("ValidateLaunch(%v) = nil, want error", argv)
		}
	}
	if err := ValidateLaunch("codex-yolo", []string{"codex", "--no-daemon", "--dangerously-bypass-approvals-and-sandbox", "resume", "--last"}); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareLaunchKeepsStatePrivate(t *testing.T) {
	source, state := t.TempDir(), filepath.Join(t.TempDir(), "agent-state")
	for name, contents := range map[string]string{"auth.json": "login", "config.toml": "required MCP", "AGENTS.md": "instructions"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := PrepareLaunch(PrepareLaunchIn{ID: "codex-yolo", Source: source, State: state}); err != nil {
		t.Fatal(err)
	}
	if got := LaunchEnv("codex-yolo", state); got["CODEX_HOME"] != state {
		t.Fatalf("CODEX_HOME = %q, want %q", got["CODEX_HOME"], state)
	}
	for _, name := range []string{"config.toml", "AGENTS.md"} {
		if _, err := os.Stat(filepath.Join(state, name)); !os.IsNotExist(err) {
			t.Fatalf("host %s imported: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "auth.json"), []byte("session-login"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareLaunch(PrepareLaunchIn{ID: "codex-yolo", Source: source, State: state}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{filepath.Join(source, "auth.json"): "login", filepath.Join(state, "auth.json"): "session-login"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("read %s = %q, %v; want %q", path, got, err, want)
		}
	}
}

// A seed that fails part-way must leave no state behind: an existing
// directory is never seeded again.
func TestPrepareLaunchFailedSeedLeavesNoState(t *testing.T) {
	source, parent := t.TempDir(), t.TempDir()
	state := filepath.Join(parent, "agent-state")
	if err := os.WriteFile(filepath.Join(source, "auth.json"), []byte("login"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := writeLogin
	writeLogin = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	t.Cleanup(func() { writeLogin = orig })
	if err := PrepareLaunch(PrepareLaunchIn{ID: "codex-yolo", Source: source, State: state}); err == nil {
		t.Fatal("failed seed reported success")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("left behind after a failed seed: %v %v", entries, err)
	}
	writeLogin = orig
	if err := PrepareLaunch(PrepareLaunchIn{ID: "codex-yolo", Source: source, State: state}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(state, "auth.json")); err != nil || string(got) != "login" {
		t.Fatalf("retry did not seed the login: %q %v", got, err)
	}
	if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("state mode: %v %v", fi, err)
	}
}

// The split executor's state is prepared with no source: it must get no
// login, whatever directory airbag runs from.
func TestPrepareLaunchWithoutSourceCopiesNoLogin(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "auth.json"), []byte("login"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	state := filepath.Join(t.TempDir(), "agent-state")
	if err := PrepareLaunch(PrepareLaunchIn{ID: "codex-yolo-split", State: state}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "auth.json")); !os.IsNotExist(err) {
		t.Fatalf("login copied without a source: %v", err)
	}
}

func TestPrepareLaunchRejectsStateSymlink(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	target := t.TempDir()
	if err := os.Symlink(target, state); err != nil {
		t.Fatal(err)
	}
	if err := PrepareLaunch(PrepareLaunchIn{ID: "codex-yolo", Source: t.TempDir(), State: state}); err == nil {
		t.Fatal("state symlink accepted; want error")
	}
}

func TestPrepareLaunchRejectsAuthSymlink(t *testing.T) {
	source := t.TempDir()
	if err := os.Symlink(filepath.Join(t.TempDir(), "secret"), filepath.Join(source, "auth.json")); err != nil {
		t.Fatal(err)
	}
	if err := PrepareLaunch(PrepareLaunchIn{ID: "codex-yolo", Source: source, State: filepath.Join(t.TempDir(), "state")}); err == nil {
		t.Fatal("auth symlink accepted; want error")
	}
}

func TestPrepareLaunchWithoutFileLogin(t *testing.T) {
	if err := PrepareLaunch(PrepareLaunchIn{ID: "codex-yolo", Source: t.TempDir(), State: filepath.Join(t.TempDir(), "state")}); err != nil {
		t.Fatalf("no file login: %v", err)
	}
}

func TestPrepareLaunchRejectsFIFO(t *testing.T) {
	source := t.TempDir()
	path := filepath.Join(source, "auth.json")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- PrepareLaunch(PrepareLaunchIn{ID: "codex-yolo", Source: source, State: filepath.Join(t.TempDir(), "state")})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO login accepted; want error")
		}
	case <-time.After(time.Second):
		f, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		<-done
		t.Fatal("opening FIFO login blocked; want immediate refusal")
	}
}
