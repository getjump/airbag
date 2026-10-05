//go:build linux

// runtimecheck performs benign boundary/policy probes, never an attestation.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type config struct{ Canary, Original, Address, TLSURL, DeniedURL string }

func run() error {
	b, err := os.ReadFile("/check.json")
	if err != nil {
		return err
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	checks := map[string]bool{}
	_, err = os.ReadFile(c.Canary)
	checks["host_canary_hidden"] = os.IsNotExist(err) || os.IsPermission(err)
	err = os.WriteFile(filepath.Join(c.Original, "escaped"), []byte("forbidden"), 0o600)
	checks["original_write_denied"] = err != nil
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(context.Background(), "tcp", c.Address)
	checks["direct_egress_denied"] = err != nil
	if conn != nil {
		_ = conn.Close()
	}
	// unshare(CLONE_NEWUSER) fails with EINVAL in any multithreaded
	// process, a Go program included, so it proves nothing; a child
	// cloned into a new user namespace does.
	child := exec.CommandContext(context.Background(), "/proc/self/exe", "userns-child")
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
	checks["user_namespace_denied"] = child.Start() != nil
	if child.Process != nil {
		_ = child.Wait()
	}
	_, _, errno := unix.RawSyscall(unix.SYS_CLONE3, 0, 0, 0)
	checks["clone3_unavailable"] = errno == unix.ENOSYS
	checks["host_token_hidden"] = os.Getenv("BOUND_SOURCE_TOKEN") == ""
	checks["placeholder_present"] = os.Getenv("CHECK_TOKEN") != "" && os.Getenv("CHECK_TOKEN") != "benign-runtime-bound-token"
	proxy, err := url.Parse(os.Getenv("HTTPS_PROXY"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	b, err = os.ReadFile("/run/airbag/ca-bundle.pem")
	if err != nil {
		return err
	}
	if !roots.AppendCertsFromPEM(b) {
		return fmt.Errorf("CA bundle invalid")
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: tlsConfig(roots)}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, c.TLSURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("CHECK_TOKEN"))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("credential proxy: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	checks["credential_used_and_response_masked"] = resp.StatusCode == http.StatusOK && !strings.Contains(string(body), "benign-runtime-bound-token") && strings.Contains(string(body), os.Getenv("CHECK_TOKEN"))
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, c.DeniedURL, nil)
	if err != nil {
		return err
	}
	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("policy denial: %w", err)
	}
	body, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	checks["external_policy_denied_allowed_host"] = resp.StatusCode == http.StatusForbidden && strings.Contains(string(body), "runtime-deny-localhost")
	if err := os.WriteFile("seed.txt", []byte("changed in guest\n"), 0o600); err != nil {
		return err
	}
	if err := os.Remove("removed.txt"); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.WriteFile("result.txt", []byte("reviewable output\n"), 0o600); err != nil {
		return err
	}
	if err := exec.CommandContext(context.Background(), "/run/airbag/bin/publisher", "send", "result.txt").Run(); err != nil {
		return fmt.Errorf("outbox: %w", err)
	}
	if len(os.Args) == 1 {
		if err := os.WriteFile("main.go", []byte("package main\nfunc main(){}\n"), 0o600); err != nil {
			return err
		}
		started := time.Now()
		cmd := exec.CommandContext(context.Background(), "/usr/local/go/bin/go", "build", "-p=1", "-o", "built", "main.go")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOMAXPROCS=1", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("offline build: %w: %s", err, out)
		}
		fmt.Printf("BUILD_SECONDS %.6f\n", time.Since(started).Seconds())
		checks["offline_go_build"] = true
	}
	for name, ok := range checks {
		if !ok {
			return fmt.Errorf("check failed: %s", name)
		}
	}
	b, err = json.Marshal(checks)
	if err != nil {
		return err
	}
	fmt.Println("RUNTIME_CHECK " + string(b))
	return nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "userns-child" {
		return // started only if a user namespace could be created
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
