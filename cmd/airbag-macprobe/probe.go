package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// probe is the state the checks share.
type probe struct {
	opts    options
	dir     string // the temporary directory, resolved
	home    string
	tag     string // marks the Seatbelt check's denials in the log
	mnt     string // the NFS mount point, once mounted
	mounted bool
	srv     *nfsServer
}

// run runs a command with a timeout and returns its combined output.
func run(timeout time.Duration, dir string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %s", timeout)
	}
	return string(out), err
}

// shq quotes s for sh.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// markers parses "key=value" lines.
func markers(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && !strings.ContainsAny(k, " \t") {
			m[k] = v
		}
	}
	return m
}

// mismatches compares markers with what is expected.
func mismatches(got, want map[string]string) []string {
	var bad []string
	for _, k := range sortedKeys(want) {
		if got[k] != want[k] {
			bad = append(bad, fmt.Sprintf("%s=%s (want %s)", k, orNone(got[k]), want[k]))
		}
	}
	return bad
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	for i := range ks {
		for j := i + 1; j < len(ks); j++ {
			if ks[j] < ks[i] {
				ks[i], ks[j] = ks[j], ks[i]
			}
		}
	}
	return ks
}

const tlsClientArg = "__tls_client"

// tlsClient fetches url through HTTPS_PROXY and prints the outcome. It
// runs inside the sandbox in the TLS check.
func tlsClient(url string) int {
	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		fmt.Println("tls=error", err)
		return 1
	}
	resp.Body.Close()
	fmt.Println("tls=ok", resp.Status)
	return 0
}

// homeDir is $HOME, or the account's home when HOME is unset or not a
// usable path (some launchd and CI jobs): S1 writes a file there, and
// the report shortens it to "~", which an empty or "/" home would put
// everywhere.
func homeDir() (string, error) {
	usable := func(h string) bool { return filepath.IsAbs(h) && filepath.Clean(h) != "/" }
	if h, err := os.UserHomeDir(); err == nil && usable(h) {
		return h, nil
	}
	if u, err := user.Current(); err == nil && usable(u.HomeDir) {
		return u.HomeDir, nil
	}
	return "", errors.New("no home directory: set HOME to your home")
}

// viaProxy is env with every proxy setting Go reads replaced by one
// HTTPS proxy: an inherited NO_PROXY would send the request around it.
func viaProxy(env []string, port int) []string {
	var out []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(k) {
		case "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY":
			continue
		}
		out = append(out, kv)
	}
	return append(out, fmt.Sprintf("HTTPS_PROXY=http://127.0.0.1:%d", port))
}

func seconds(d time.Duration) float64 { return d.Seconds() }

func timed(f func() error) (time.Duration, error) {
	t := time.Now()
	err := f()
	return time.Since(t), err
}

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o644) }
