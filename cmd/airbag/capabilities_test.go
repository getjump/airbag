package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestResumeCannotDowngradeRecordedBoundary(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := t.TempDir()
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
