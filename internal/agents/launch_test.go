package agents

import (
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
		{"default", []string{"yolo"}, []string{"--", "codex", "--no-daemon", "--dangerously-bypass-approvals-and-sandbox", "-c", "allow_login_shell=false"}, false},
		{"explicit login override", []string{"yolo", "--", "-c", "allow_login_shell=true"}, []string{"--", "codex", "--no-daemon", "--dangerously-bypass-approvals-and-sandbox", "-c", "allow_login_shell=false", "-c", "allow_login_shell=true"}, false},
		{"arguments", []string{"yolo", "--session", "last", "--allow-trustd=false", "--", "resume", "--last", "-m", "model"}, []string{"--session", "last", "--allow-trustd=false", "--", "codex", "--no-daemon", "--dangerously-bypass-approvals-and-sandbox", "-c", "allow_login_shell=false", "resume", "--last", "-m", "model"}, false},
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
	for _, name := range []string{"AGENTS.md"} {
		if _, err := os.Stat(filepath.Join(state, name)); !os.IsNotExist(err) {
			t.Fatalf("host %s imported: %v", name, err)
		}
	}
	if got, err := os.ReadFile(filepath.Join(state, "config.toml")); err != nil || string(got) != "allow_login_shell = false\n" {
		t.Fatalf("private defaults = %q, %v; want nonlogin shell setting only", got, err)
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

func TestPrepareLaunchKeepsExistingConfig(t *testing.T) {
	state := t.TempDir()
	path := filepath.Join(state, "config.toml")
	want := "model = \"chosen\"\n"
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareLaunch(PrepareLaunchIn{ID: "codex-yolo", Source: t.TempDir(), State: state}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != want {
		t.Fatalf("existing config = %q, %v; want %q", got, err, want)
	}
}

func TestPrepareLaunchSeedsMissingConfig(t *testing.T) {
	state := t.TempDir()
	if err := PrepareLaunch(PrepareLaunchIn{ID: "codex-yolo", Source: t.TempDir(), State: state}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(state, "config.toml")); err != nil || string(got) != "allow_login_shell = false\n" {
		t.Fatalf("missing config = %q, %v; want nonlogin shell default", got, err)
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
