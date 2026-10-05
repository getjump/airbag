package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/getjump/airbag/internal/sandbox"
	"github.com/getjump/airbag/internal/secretfs"
	"github.com/getjump/airbag/internal/session"
)

func cmdCapabilities(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	fs.SetOutput(out)
	backend := fs.String("backend", "native", "backend to describe")
	jsonOutput := fs.Bool("json", false, "print the compiled backend description as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("usage: airbag capabilities [--backend=native|gvisor|microvm] [--json]")
	}
	b, err := sandbox.SelectBackend(*backend, "any")
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(b)
	}
	// Doctor checks what native needs. An optional runtime's files, KVM,
	// cp and mkfs.ext4 are checked by run, before the session starts.
	check := "use airbag doctor"
	if b.Name != "native" {
		check = "airbag run --backend=" + b.Name + " checks the runtime before the session starts; airbag doctor checks native only"
	}
	fmt.Fprintf(out, "backend: %s (%s)\nisolation: %s\nmechanism: %s\nworkspace: %s; HOME branch: %t\negress: %s\nreadiness: %s (%s)\n",
		b.Name, b.Platform, b.Isolation, b.Mechanism, b.WorkspaceBranch, b.HomeBranch, b.Egress, b.Readiness, check)
	for _, limitation := range b.Limitations {
		fmt.Fprintln(out, "limit: "+limitation)
	}
	return nil
}

// validateExecution runs before Resume changes any session files. Legacy
// metadata without these fields describes native sessions and remains readable.
func validateExecution(s *session.Session, b sandbox.Backend, requested string) error {
	if s.Backend != "" && s.Backend != b.Name {
		return fmt.Errorf("session backend %q cannot resume on %s", s.Backend, b.Name)
	}
	if s.Isolation != "" && s.Isolation != b.Isolation {
		return fmt.Errorf("session isolation %q cannot resume on %s", s.Isolation, b.Isolation)
	}
	if s.RequireIsolation != "" {
		if err := b.Require(s.RequireIsolation); err != nil {
			return err
		}
	}
	return b.Require(requested)
}

// validateRuntimeResume refuses what an optional runtime cannot carry on:
// the runtime policies, and a secret file in the session's copy, which
// the runtime would hand to the agent unmediated. PreflightRuntime checks
// the real workspace; a file the earlier run wrote is only in the copy.
func validateRuntimeResume(s *session.Session, b sandbox.Backend) error {
	if b.Name == "native" {
		return nil
	}
	if s.FilePolicy || s.ExecPolicy || s.RuntimeProfile || s.FileCache != "" && s.FileCache != "off" || s.RuntimeAudit == "buffered" {
		return fmt.Errorf("session %s runs with runtime policy options, which %s does not run; resume it on the native backend", s.ID, b.Name)
	}
	// No copy: run makes it again from the workspace, which
	// PreflightRuntime checked.
	if _, err := os.Lstat(s.CloneDir()); errors.Is(err, fs.ErrNotExist) { //nolint:gosec // the session's own directory under AIRBAG_HOME, the user's choice
		return nil
	}
	files, err := secretfs.FindAll(s.CloneDir())
	if err != nil {
		return fmt.Errorf("session %s's copy cannot be checked for secret files, which %s cannot mediate: %w; review the session, then apply or discard it", s.ID, b.Name, err)
	}
	if len(files) != 0 {
		return fmt.Errorf("session %s's copy holds a secret file (%s), which %s cannot mediate; review the session, then apply or discard it", s.ID, files[0], b.Name)
	}
	return nil
}
