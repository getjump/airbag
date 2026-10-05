package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/getjump/airbag/internal/sandbox"
	"github.com/getjump/airbag/internal/session"
)

func cmdCapabilities(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	fs.SetOutput(out)
	jsonOutput := fs.Bool("json", false, "print the compiled backend description as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("usage: airbag capabilities [--json]")
	}
	b := sandbox.NativeBackend()
	if *jsonOutput {
		return json.NewEncoder(out).Encode(b)
	}
	fmt.Fprintf(out, "backend: %s (%s)\nisolation: %s\nmechanism: %s\nworkspace: %s; HOME branch: %t\negress: %s\nreadiness: %s (use airbag doctor)\n",
		b.Name, b.Platform, b.Isolation, b.Mechanism, b.WorkspaceBranch, b.HomeBranch, b.Egress, b.Readiness)
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
