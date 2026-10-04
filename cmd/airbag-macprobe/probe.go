package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
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

func seconds(d time.Duration) float64 { return d.Seconds() }

func timed(f func() error) (time.Duration, error) {
	t := time.Now()
	err := f()
	return time.Since(t), err
}

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o644) }
