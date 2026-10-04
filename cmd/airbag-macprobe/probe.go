package main

import (
	"context"
	"encoding/json"
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
	return runEnv(timeout, dir, nil, name, args...)
}

// runEnv is run with the environment env (nil: this process's).
func runEnv(timeout time.Duration, dir string, env []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // the probe's own commands, with its own arguments
	cmd.Dir = dir
	cmd.Env = env
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
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil) //nolint:gosec // the URL the probe passes itself for its TLS check
	if err != nil {
		fmt.Println("tls=error", err)
		return 1
	}
	resp, err := c.Do(req) //nolint:gosec // the URL the probe passes itself for its TLS check
	if err != nil {
		fmt.Println("tls=error", err)
		return 1
	}
	resp.Body.Close()
	fmt.Println("tls=ok", resp.Status)
	return 0
}

// tlsTry is one run of the TLS client: whether it printed tls=ok, and
// what it printed.
type tlsTry struct {
	ok  bool
	out string
}

// tlsVerdict is T1's status and reason from its control outside the
// profile and its requests inside it without and with trustd. Only a
// control that got through makes the other two say something about the
// profile; without one, T1 is skipped.
func tlsVerdict(control, without, with tlsTry) (Status, string) {
	switch {
	case !control.ok:
		return Info, "skipped: the control request did not get through: " + orNone(firstLine(control.out))
	case without.ok:
		return Pass, "certificate verified without trustd"
	case with.ok:
		return Fail, "works only with trustd allowed (as sandbox-runtime reports)"
	default:
		return Fail, "fails with and without trustd: " + firstLine(with.out)
	}
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

// gitEnv is env for git in the probe's own repository: no GIT_* from
// the caller (GIT_DIR would point git at the user's real repository), and
// no system or global config (hooks, signing, templates).
func gitEnv(env []string) []string {
	var out []string
	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
}

// gitArgs are prepended to every git command the probe runs.
var gitArgs = []string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "user.email=probe@example.com", "-c", "user.name=probe"}

// violationLines picks the Seatbelt denials that name file from the
// output of `log show --style ndjson`: entries whose message is a
// "deny" and contains file. Other lines, such as the "Filtering the log
// data using ..." header that repeats the predicate, are not entries.
func violationLines(out, file string) []string {
	var hits []string
	for _, l := range strings.Split(out, "\n") {
		var e struct {
			EventMessage string `json:"eventMessage"`
		}
		if json.Unmarshal([]byte(l), &e) != nil {
			continue
		}
		if strings.Contains(e.EventMessage, "deny") && strings.Contains(e.EventMessage, file) {
			hits = append(hits, e.EventMessage)
		}
	}
	return hits
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

// platformTrust is env without SSL_CERT_FILE and SSL_CERT_DIR, and the
// names it removed. With either set, a program on macOS whose go.mod
// says go 1.27 or later (the probe's does) checks certificates against
// those files and never asks trustd. T1 asks whether the platform
// verifier works without trustd: what a program with an earlier go line
// always uses on macOS, whatever Go builds it, and a later one uses
// without the variables.
func platformTrust(env []string) (out, removed []string) {
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if k == "SSL_CERT_FILE" || k == "SSL_CERT_DIR" {
			removed = append(removed, k)
			continue
		}
		out = append(out, kv)
	}
	return out, removed
}

func seconds(d time.Duration) float64 { return d.Seconds() }

func timed(f func() error) (time.Duration, error) {
	t := time.Now()
	err := f()
	return time.Since(t), err
}

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o644) }
