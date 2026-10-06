package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/sandbox"
	"github.com/getjump/airbag/internal/session"
)

func TestExecutionRequirementFailsBeforeSessionCreation(t *testing.T) {
	for _, args := range [][]string{
		{"--backend=gvisor", "--", "true"},
		{"--backend=microvm", "--", "true"},
		{"--backend=typo", "--", "true"},
		{"--require-isolation=application-kernel", "--", "true"},
		{"--require-isolation=virtual-machine", "--", "true"},
		{"--require-isolation=typo", "--", "true"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "sessions")
			t.Setenv("AIRBAG_HOME", root)
			t.Setenv("AIRBAG_SESSION", "")
			code, err := cmdRun(args)
			if code != 2 || err == nil {
				t.Fatalf("code=%d err=%v", code, err)
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatalf("failed preflight created session files: %v", err)
			}
		})
	}
}

// The runtime policies run in the native sandbox only: an optional
// runtime asked for one is refused before anything else, rather than run
// without it.
func TestOptionalRuntimeRefusesRuntimePolicies(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the runtime policies are Linux options")
	}
	for _, args := range [][]string{
		{"--backend=gvisor", "--exec-policy", "--", "true"},
		{"--backend=gvisor", "--fs-policy", "--", "true"},
		{"--backend=microvm", "--runtime-audit=buffered", "--", "true"},
		{"--backend=microvm", "--fs-cache=sealed", "--", "true"},
		{"--backend=gvisor", "--runtime-profile", "--", "true"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "sessions")
			t.Setenv("AIRBAG_HOME", root)
			t.Setenv("AIRBAG_SESSION", "")
			code, err := cmdRun(args)
			if code != 2 || err == nil || !strings.Contains(err.Error(), "runtime policy") {
				t.Fatalf("code=%d err=%v", code, err)
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatalf("created session files: %v", err)
			}
		})
	}
}

func TestResumeCannotDowngradeRecordedBoundary(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := t.TempDir()
	for _, d := range []string{ws} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Backend: "native", RequireIsolation: "virtual-machine"})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(s.RunDir(), "keep")
	if err := os.WriteFile(marker, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(s.Dir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.ResumeChecked("last", ws, func(s *session.Session) error {
		return validateExecution(s, sandbox.NativeBackend(), "any")
	})
	if err == nil {
		t.Fatal("resume silently discarded a saved isolation requirement")
	}
	after, err := os.ReadFile(filepath.Join(s.Dir, "meta.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("refused resume changed metadata: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("refused resume cleaned the run directory: %v", err)
	}
	for _, meta := range []session.Meta{{Backend: "microvm"}, {Isolation: "virtual-machine"}} {
		if validateExecution(&session.Session{Meta: meta}, sandbox.NativeBackend(), "any") == nil {
			t.Fatalf("accepted foreign session: %+v", meta)
		}
	}
	if err := validateExecution(&session.Session{}, sandbox.NativeBackend(), "any"); err != nil {
		t.Fatalf("legacy native session rejected: %v", err)
	}
}

func TestCapabilitiesDoesNotProbeOrCreateSessions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sessions")
	t.Setenv("AIRBAG_HOME", root)
	var out bytes.Buffer
	if err := cmdCapabilities([]string{"--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var b sandbox.Backend
	if err := json.Unmarshal(out.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.Schema != 1 || b.Isolation != "shared-kernel" || b.Readiness != "not-probed" {
		t.Fatalf("misleading capabilities: %+v", b)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("capabilities created session files: %v", err)
	}
}

// Doctor checks native only, so an optional backend's text names the
// check run makes instead.
func TestCapabilitiesNamesTheBackendsCheck(t *testing.T) {
	var out bytes.Buffer
	if err := cmdCapabilities(nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "(use airbag doctor)") {
		t.Errorf("native does not point to doctor:\n%s", out.String())
	}
	if runtime.GOOS != "linux" {
		return
	}
	for _, name := range []string{"gvisor", "microvm"} {
		out.Reset()
		if err := cmdCapabilities([]string{"--backend=" + name}, &out); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "(use airbag doctor)") || !strings.Contains(out.String(), "airbag run --backend="+name+" checks the runtime") {
			t.Errorf("%s points to doctor, which does not check it:\n%s", name, out.String())
		}
	}
}

// A secret file the earlier run left in the copy is only there, so
// resume checks the copy as well: the optional runtime would hand it to
// the agent without the native mediation.
func TestOptionalResumeRefusesASecretInTheCopy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("optional runtimes are Linux only")
	}
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := t.TempDir()
	gvisor, err := sandbox.SelectBackend("gvisor", "any")
	if err != nil {
		t.Fatal(err)
	}
	// A stopped session whose copy holds a source file.
	stopped := func() *session.Session {
		s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Backend: "gvisor"})
		if err != nil {
			t.Fatal(err)
		}
		s.Status = session.StatusStopped
		if err := s.Save(); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(s.CloneDir(), "app"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(s.CloneDir(), "app", "main.go"), []byte("package main"), 0o600); err != nil {
			t.Fatal(err)
		}
		return s
	}
	resume := func(s *session.Session) error {
		_, err := session.ResumeChecked(s.ID, ws, func(s *session.Session) error { return validateRuntimeResume(s, gvisor) })
		return err
	}
	// A resume that goes through holds the session's run lock until this
	// process ends, so it gets a session of its own; a refused one lets
	// the lock go.
	if err := resume(stopped()); err != nil {
		t.Fatalf("a copy without secret files is refused: %v", err)
	}
	s := stopped()
	if err := os.WriteFile(filepath.Join(s.CloneDir(), "app", ".env"), []byte("TOKEN=x"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(s.Dir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := resume(s); err == nil || !strings.Contains(err.Error(), filepath.Join("app", ".env")) {
		t.Fatalf("a secret file in the copy is not refused: %v", err)
	}
	if after, err := os.ReadFile(filepath.Join(s.Dir, "meta.json")); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("refused resume changed metadata: %v", err)
	}
	if err := validateRuntimeResume(s, sandbox.NativeBackend()); err != nil {
		t.Fatalf("native mediates the file and is refused: %v", err)
	}
	// A directory the check cannot read is refused too: the agent owns
	// the copy and can make it readable again. Root reads it and finds
	// the file.
	if err := os.Remove(filepath.Join(s.CloneDir(), "app", ".env")); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(s.CloneDir(), "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "id_rsa"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	// Root reads it and finds the file; anyone else cannot read it.
	want := "cannot be checked"
	if os.Geteuid() == 0 {
		want = "holds a secret file"
	}
	if err := resume(s); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("a directory the check cannot read: %v, want %q", err, want)
	}
	// Without a copy, run makes one from the checked workspace.
	if err := os.Chmod(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(s.CloneDir()); err != nil {
		t.Fatal(err)
	}
	if err := resume(s); err != nil {
		t.Fatalf("a session without a copy is refused: %v", err)
	}
}

// A saved session that asks for a runtime policy is not resumed on an
// optional runtime, which would run it without the policy.
func TestOptionalResumeRefusesRuntimePolicies(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("optional runtimes are Linux only")
	}
	gvisor, err := sandbox.SelectBackend("gvisor", "any")
	if err != nil {
		t.Fatal(err)
	}
	for name, meta := range map[string]session.Meta{
		"fs-policy":       {FilePolicy: true},
		"exec-policy":     {ExecPolicy: true},
		"runtime-profile": {RuntimeProfile: true},
		"fs-cache":        {FileCache: "sealed"},
		"buffered audit":  {RuntimeAudit: "buffered"},
	} {
		meta.ID, meta.Backend = "s-1", "gvisor"
		err := validateRuntimeResume(&session.Session{Meta: meta, Dir: t.TempDir()}, gvisor)
		if err == nil || !strings.Contains(err.Error(), "runtime policy") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := validateRuntimeResume(&session.Session{Meta: session.Meta{ID: "s-1", Backend: "gvisor", FileCache: "off", RuntimeAudit: "durable"}, Dir: t.TempDir()}, gvisor); err != nil {
		t.Errorf("the defaults are refused: %v", err)
	}
}
