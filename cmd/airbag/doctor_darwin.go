//go:build darwin

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/getjump/airbag/internal/session"
)

// cmdDoctor checks what the macOS prototype needs: Seatbelt, and an APFS
// clone from the workspace to the session directory.
func cmdDoctor() error {
	ok := true
	check := func(name string, good bool, hint string) {
		mark := "ok  "
		if !good {
			mark, ok = "FAIL", false
		}
		fmt.Printf("%s %s\n", mark, name)
		if !good && hint != "" {
			fmt.Println("     " + strings.ReplaceAll(hint, "\n", "\n     "))
		}
	}
	v, _ := exec.CommandContext(context.Background(), "/usr/bin/sw_vers", "-productVersion").Output()
	fmt.Printf("note macOS %s: the macOS port is a prototype (docs/macos.md)\n", strings.TrimSpace(string(v)))

	_, err := os.Stat("/usr/bin/sandbox-exec")
	check("sandbox-exec (Seatbelt) present", err == nil, "airbag runs the agent under sandbox-exec")
	if err == nil {
		out, err := exec.CommandContext(context.Background(), "/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true").CombinedOutput()
		check("sandbox-exec runs a profile", err == nil, strings.TrimSpace(string(out)))
	}

	root := session.Root()
	_ = os.MkdirAll(root, 0o700)
	cwd, _ := os.Getwd()
	src, err := os.CreateTemp(cwd, ".airbag-doctor-")
	if err == nil {
		_ = src.Close()
		dst := filepath.Join(root, filepath.Base(src.Name()))
		out, cerr := exec.CommandContext(context.Background(), "/bin/cp", "-c", src.Name(), dst).CombinedOutput() //nolint:gosec // copies doctor's own temporary file
		check("APFS clone from this directory to "+root, cerr == nil,
			"the branch is an APFS clone; without one airbag copies the workspace in full: "+strings.TrimSpace(string(out)))
		_ = os.Remove(dst)
		_ = os.Remove(src.Name())
	}
	if os.Getuid() == 0 {
		fmt.Println("note: running as root; run airbag as your user")
	}
	if !ok {
		return fmt.Errorf("this machine is not ready")
	}
	return nil
}
