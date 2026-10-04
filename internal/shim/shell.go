package shim

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/control"
	"github.com/getjump/airbag/internal/models"
	"github.com/getjump/airbag/internal/secretfs"
)

// Shell stands in for bash and sh inside the sandbox. For `-c SCRIPT` it
// parses the script, predicts each command's effects and reports them,
// then runs the real shell. The real shell does the work, so scripts
// behave exactly as before; prediction only adds context. When output
// goes to a pipe (an agent's tool call), known secret values in it are
// masked.
func Shell(name string, args []string) {
	real, err := lookPathSkipping(name, BinDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airbag: %s not found\n", name)
		os.Exit(127)
	}
	argv := append([]string{name}, args...)
	script, ok := scriptArg(args)
	if !ok {
		execOrDie(real, argv)
	}
	cmds, perr := models.Analyze(script)
	report := control.Exec{Shell: name, Script: clip(script, 4000), Commands: cmds}
	if perr != nil {
		report.ParseError = perr.Error()
	}
	if v := control.ReportExec(report); v.Verdict != "allow" && v.Verdict != "" {
		fmt.Fprintln(os.Stderr, v.Message)
		os.Exit(126)
	}

	// Masking needs a pipe; background jobs would hold it open, so such
	// scripts run unfiltered.
	secrets := knownSecrets()
	if len(secrets) == 0 || isTerminal(1) || models.Background(script) {
		execOrDie(real, argv)
	}
	os.Exit(runMasked(real, argv, secrets))
}

func execOrDie(path string, argv []string) {
	err := syscall.Exec(path, argv, os.Environ())
	fmt.Fprintf(os.Stderr, "airbag: exec %s: %v\n", path, err)
	os.Exit(126)
}

// scriptArg finds SCRIPT in `bash [opts] -c SCRIPT [name args...]`;
// options may be clustered (-lc, -ec).
func scriptArg(args []string) (string, bool) {
	seenC := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-o" || a == "+o" || a == "-O" || a == "+O" || a == "--rcfile" || a == "--init-file":
			i++
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+"):
			if strings.HasPrefix(a, "-") && strings.Contains(a[1:], "c") {
				seenC = true
			}
		default:
			if !seenC {
				return "", false // bash script.sh: a file, not -c
			}
			return a, true
		}
	}
	return "", false
}

func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	return err == nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

type secret struct {
	name  string
	value []byte
}

// knownSecrets: values from the workspace's .env files and from
// environment variables whose names look like credentials.
func knownSecrets() []secret {
	seen := map[string]bool{}
	var out []secret
	add := func(name, v string) {
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if len(v) >= 8 && !seen[v] {
			seen[v] = true
			out = append(out, secret{name, []byte(v)})
		}
	}
	if ws := os.Getenv("AIRBAG_WORKSPACE"); ws != "" {
		for _, f := range secretfs.Open(ws) {
			base := filepath.Base(f.Rel)
			sc := bufio.NewScanner(f.F)
			sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
			for sc.Scan() {
				line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "export "))
				if base == ".env" || strings.HasPrefix(base, ".env.") {
					if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(k, "#") {
						add(k, v)
					}
					continue
				}
				// Other secret files (keys, .npmrc, ...) are not KEY=value;
				// mask each substantial line, so a key printed out is caught.
				if len(line) >= 16 && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "-----") {
					add(f.Rel, line)
				}
			}
			f.F.Close()
		}
	}
	// Placeholders for credentials airbag substitutes are not secrets.
	placeholders := strings.Split(os.Getenv("AIRBAG_PLACEHOLDERS"), ",")
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		u := strings.ToUpper(k)
		if strings.Contains(u, "PROXY") || slices.Contains(placeholders, k) {
			continue
		}
		for _, w := range []string{"TOKEN", "SECRET", "PASSWORD", "API_KEY", "APIKEY", "PRIVATE_KEY", "CREDENTIAL"} {
			if strings.Contains(u, w) {
				add(k, v)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].value) > len(out[j].value) })
	return out
}

// runMasked runs the real shell with stdout and stderr filtered. Once
// the shell exits, output still in flight is drained for a moment; a
// process that kept the pipe open does not keep the shim alive.
func runMasked(path string, argv []string, secrets []secret) int {
	cmd := exec.Command(path, argv[1:]...)
	cmd.Args[0] = argv[0]
	cmd.Stdin = os.Stdin
	out, errw := newMasker(os.Stdout, secrets), newMasker(os.Stderr, secrets)
	var drained []chan struct{}
	for _, m := range []*masker{out, errw} {
		r, w, err := os.Pipe()
		if err != nil {
			return 126
		}
		if m == out {
			cmd.Stdout = w
		} else {
			cmd.Stderr = w
		}
		done := make(chan struct{})
		drained = append(drained, done)
		go func(m *masker, r *os.File) {
			_, _ = io.Copy(m, r)
			close(done)
		}(m, r)
		defer w.Close()
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "airbag: %v\n", err)
		return 126
	}
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	cmd.Stdout.(*os.File).Close() // the child holds its own copies
	cmd.Stderr.(*os.File).Close()
	err := cmd.Wait()
	for _, d := range drained {
		select {
		case <-d:
		case <-time.After(200 * time.Millisecond):
		}
	}
	out.Flush()
	errw.Flush()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if st, ok := ee.Sys().(syscall.WaitStatus); ok && st.Signaled() {
			return 128 + int(st.Signal())
		}
		return ee.ExitCode()
	}
	if err != nil {
		return 1
	}
	return 0
}

// masker replaces secret values in a stream. It holds back a tail as
// long as the longest secret, so a value split across writes is still
// caught.
type masker struct {
	w       io.Writer
	secrets []secret
	buf     []byte
	keep    int
}

func newMasker(w io.Writer, secrets []secret) *masker {
	keep := 0
	for _, s := range secrets {
		keep = max(keep, len(s.value)-1)
	}
	return &masker{w: w, secrets: secrets, keep: keep}
}

func (m *masker) Write(p []byte) (int, error) {
	m.buf = append(m.buf, p...)
	m.mask()
	if n := len(m.buf) - m.keep; n > 0 {
		if _, err := m.w.Write(m.buf[:n]); err != nil {
			return 0, err
		}
		m.buf = append(m.buf[:0], m.buf[n:]...)
	}
	return len(p), nil
}

func (m *masker) mask() {
	for _, s := range m.secrets {
		if bytes.Contains(m.buf, s.value) {
			m.buf = bytes.ReplaceAll(m.buf, s.value, []byte("[airbag: masked "+s.name+"]"))
		}
	}
}

func (m *masker) Flush() {
	m.mask()
	_, _ = m.w.Write(m.buf)
	m.buf = m.buf[:0]
}
