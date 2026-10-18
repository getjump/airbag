package sandbox

import (
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

func TestAgentTempDirectory(t *testing.T) {
	t.Setenv("CLAUDE_CODE_TMPDIR", "/tmp/host-claude-temp")
	s := &session.Session{Meta: session.Meta{ID: "s-test"}}
	env := agentEnvFor(s, "127.0.0.1:12345", "/session/bin", "/session/private-temp", nil)
	var got []string
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, "CLAUDE_CODE_TMPDIR="); ok {
			got = append(got, value)
		}
	}
	if len(got) != 1 || got[0] != "/session/private-temp" {
		t.Fatalf("CLAUDE_CODE_TMPDIR=%q, want one /session/private-temp entry", got)
	}
}

// A sandboxed process must get no handle to WSL interop: the socket that
// launches Windows processes (WSL_INTEROP), the env bridge (WSLENV), and
// the /mnt/<drive> PATH entries that resolve cmd.exe/powershell.exe all
// stay out of the agent's environment.
func TestAgentEnvDropsWSLInterop(t *testing.T) {
	t.Setenv("WSL_INTEROP", "/run/WSL/8_interop")
	t.Setenv("WSLENV", "RUNNER_TEMP/p:CI")
	t.Setenv("WSL_DISTRO_NAME", "Ubuntu-24.04")
	t.Setenv("PATH", "/usr/bin:/mnt/c/Windows/System32:/mnt/c/Windows:/home/me/bin:/mnt/d/tools")

	s := &session.Session{Meta: session.Meta{ID: "s-test"}}
	env := agentEnvFor(s, "127.0.0.1:12345", "/session/bin", "/session/private-temp", nil)

	vals := map[string]string{}
	for _, entry := range env {
		k, v, _ := strings.Cut(entry, "=")
		if _, dup := vals[k]; dup {
			t.Fatalf("duplicate env key %q", k)
		}
		vals[k] = v
	}
	if v, ok := vals["WSL_INTEROP"]; ok {
		t.Errorf("WSL_INTEROP leaked to the agent: %q", v)
	}
	if v, ok := vals["WSLENV"]; ok {
		t.Errorf("WSLENV leaked to the agent: %q", v)
	}
	path, ok := vals["PATH"]
	if !ok {
		t.Fatal("no PATH in the agent environment")
	}
	for _, p := range strings.Split(path, ":") {
		if strings.HasPrefix(p, "/mnt/c") || strings.HasPrefix(p, "/mnt/d") {
			t.Errorf("Windows-drive PATH entry %q survived in %q", p, path)
		}
	}
	for _, want := range []string{"/session/bin", "/usr/bin", "/home/me/bin"} {
		if !strings.Contains(":"+path+":", ":"+want+":") {
			t.Errorf("PATH %q dropped the Linux entry %q", path, want)
		}
	}
}
