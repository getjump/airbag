package shim

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/getjump/airbag/internal/control"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/secretfs"
)

// IsDeferred reports whether airbag was started as the shim of a
// program that a `defer:` entry names: a link of that name in BinDir.
func IsDeferred(name string) bool {
	if name == "airbag" || strings.ContainsRune(name, '/') {
		return false
	}
	st, err := os.Lstat(filepath.Join(BinDir, name))
	return err == nil && st.Mode()&os.ModeSymlink != 0
}

// Deferred stands in front of a program that a `defer:` entry names.
// A call the entry matches waits in the outbox and runs on the host
// after review; any other call runs here unchanged. Calling the program
// by its full path skips the shim and runs it in the sandbox, without
// the user's credentials.
func Deferred(name string, args []string) {
	cwd, _ := os.Getwd()
	argv := append([]string{name}, args...)
	d, err := control.Defer(outbox.Intent{Argv: argv, Cwd: cwd, Files: pins(cwd, args)})
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "airbag: could not queue %s: %v\n", name, err)
		os.Exit(1)
	case d.Refused != "":
		fmt.Fprintf(os.Stderr, "airbag: `%s` not queued: %s\n", clipLine(argv), d.Refused)
		os.Exit(126)
	case d.Queued != nil:
		fmt.Fprintf(os.Stderr, "airbag: `%s` queued as intent %s; it runs on the host after the human approves it in `airbag review`. "+
			"Its output is not available now. Do not retry.\n", clipLine(argv), d.Queued.ID)
		os.Exit(0)
	}
	real, err := lookPathSkipping(name, BinDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airbag: %s not found\n", name)
		os.Exit(127)
	}
	err = syscall.Exec(real, argv, os.Environ()) //nolint:gosec // the shim becomes the program it stands in for, inside the sandbox
	fmt.Fprintf(os.Stderr, "airbag: exec %s: %v\n", name, err)
	os.Exit(126)
}

// maxPins bounds how many arguments are looked at as files.
const maxPins = 64

// pins hashes the regular files that arguments name, as words or as
// --option=value: the command later runs only on the same content.
func pins(cwd string, args []string) map[string]string {
	out := map[string]string{}
	for i, a := range args {
		if i >= maxPins {
			break
		}
		if strings.HasPrefix(a, "-") {
			_, v, ok := strings.Cut(a, "=")
			if !ok {
				continue
			}
			a = v
		}
		if a == "" || len(a) > 4096 {
			continue
		}
		p := a
		if !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		// Reads by airbag do not taint the session, so a secret file is
		// not opened here; the host refuses calls that name one.
		if secretfs.IsSecret(filepath.Base(p)) {
			continue
		}
		if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
			continue
		}
		if sum, err := hashFile(p); err == nil {
			out[filepath.Clean(p)] = sum
		}
	}
	return out
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func clipLine(argv []string) string {
	l := outbox.Line(argv)
	if len(l) > 120 {
		return l[:120] + "…"
	}
	return l
}
