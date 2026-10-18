package policy

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func userFile(home string) string { return filepath.Join(home, ".config", "airbag", "airbag.yaml") }

func TestSimulateFromUserFile(t *testing.T) {
	home, ws := t.TempDir(), t.TempDir()
	write(t, filepath.Join(home, ".config", "airbag", "stubs", "charge.json"), `{"id":"ch_sim"}`)
	write(t, userFile(home), `
allow: [api.github.com]
simulate:
  - name: charge
    match: {method: POST, host: api.pay.test, path: /v1/charges}
    respond: {status: 201, body_file: stubs/charge.json}
  - match: {host: status.pay.test}
    respond: {status: 503}
`)
	p, err := Load(ws, home)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.Simulation.Hosts(), ","); got != "api.pay.test,status.pay.test" {
		t.Fatalf("hosts %q", got)
	}
	r := p.Simulation.Match("api.pay.test", "443", "POST", &url.URL{Path: "/v1/charges"}, nil)
	if r == nil || r.Status != 201 || string(r.Body) != `{"id":"ch_sim"}` {
		t.Fatalf("%+v", r)
	}
	// An unnamed stub is named after its file and place, as a rule is.
	if r := p.Simulation.Match("status.pay.test", "443", "GET", &url.URL{Path: "/"}, nil); r == nil || r.Stub != "airbag.yaml#2" {
		t.Fatalf("%+v", r)
	}
	if len(p.Allow) != 1 {
		t.Fatal("the rest of the file was not read as before")
	}
}

// A repository's airbag.yaml cannot simulate: its stubs would decide
// what the agent is told, the model API's answers included.
func TestWorkspaceCannotSimulate(t *testing.T) {
	home, ws := t.TempDir(), t.TempDir()
	write(t, filepath.Join(ws, "airbag.yaml"), "simulate:\n  - match: {host: api.anthropic.com}\n    respond: {body: hi}\n")
	if _, err := Load(ws, home); err == nil || !strings.Contains(err.Error(), "a repository must not decide") {
		t.Fatalf("err = %v", err)
	}
	// Nor can it slip one in malformed, to be ignored.
	write(t, filepath.Join(ws, "airbag.yaml"), "simulate: {host: x}\n")
	if _, err := Load(ws, home); err == nil {
		t.Fatal("a malformed simulate: in the workspace loaded")
	}
	write(t, filepath.Join(ws, "airbag.yaml"), "simulate: []\nallow: [x.test]\n")
	if _, err := Load(ws, home); err != nil {
		t.Fatalf("an empty simulate: %v", err)
	}
}

// The stubs are read strictly: a misspelled field is an error, not a
// stub that answers what the user did not write.
func TestSimulateStrict(t *testing.T) {
	for _, bad := range []string{
		"simulate:\n  - match: {host: a.test}\n    respond: {bodyfile: x.json}\n",
		"simulate:\n  - match: {host: a.test, paht: /x}\n",
		"simulate:\n  - host: a.test\n",
		"simulate:\n  - match: {host: a.test}\n    respond: {body: a, body_file: b.json}\n",
		"simulate:\n  - match: {host: 10.0.0.1}\n",
	} {
		home := t.TempDir()
		write(t, userFile(home), bad)
		if _, err := Load(t.TempDir(), home); err == nil {
			t.Errorf("loaded:\n%s", bad)
		}
	}
}

// A body file is read from the directory of the file that names it and
// nowhere else: not through .., an absolute path or a link, not a
// secret file, not from the home directory itself, and within the
// bound.
func TestStubBodyStaysInItsDirectory(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, ".config", "airbag")
	write(t, filepath.Join(home, ".ssh", "id_ed25519"), "PRIVATE KEY")
	write(t, filepath.Join(cfg, "stubs", ".env"), "API_TOKEN=x")
	write(t, filepath.Join(cfg, "stubs", "big.json"), strings.Repeat("x", 4<<20+1))
	write(t, filepath.Join(cfg, "stubs", "ok.json"), "ok")
	if err := os.Symlink(filepath.Join(home, ".ssh", "id_ed25519"), filepath.Join(cfg, "stubs", "key.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(cfg, "ssh")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../../.ssh/id_ed25519", filepath.Join(home, ".ssh", "id_ed25519"), "~/.ssh/id_ed25519",
		"stubs/key.json", "ssh/id_ed25519", "stubs/.env", "stubs/big.json", "stubs", "stubs/missing.json"} {
		write(t, userFile(home), "simulate:\n  - match: {host: a.test}\n    respond: {body_file: '"+name+"'}\n")
		if p, err := Load(t.TempDir(), home); err == nil {
			t.Errorf("body_file %s loaded: %q", name, p.Stubs[0].Respond.Body)
		}
	}
	write(t, userFile(home), "simulate:\n  - match: {host: a.test}\n    respond: {body_file: stubs/ok.json}\n")
	if _, err := Load(t.TempDir(), home); err != nil {
		t.Fatal(err)
	}
	// A --simulate file in the home directory itself would put all of it
	// in reach.
	write(t, filepath.Join(home, "stubs.yaml"), "simulate:\n  - match: {host: a.test}\n    respond: {body_file: .config/airbag/stubs/ok.json}\n")
	p, err := Load(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddSimulation(filepath.Join(home, "stubs.yaml"), home); err == nil || !strings.Contains(err.Error(), "home directory") {
		t.Fatalf("err = %v", err)
	}
}

// A --simulate file holds only stubs; they are tried before the user
// file's, and it is listed among the sources.
func TestAddSimulation(t *testing.T) {
	home, dir := t.TempDir(), t.TempDir()
	write(t, userFile(home), "simulate:\n  - name: general\n    match: {host: api.pay.test}\n    respond: {status: 500}\n")
	write(t, filepath.Join(dir, "body.txt"), "specific")
	write(t, filepath.Join(dir, "run.yaml"), "simulate:\n  - name: specific\n    match: {host: api.pay.test, path: /v1/x}\n    respond: {body_file: body.txt}\n")
	p, err := Load(t.TempDir(), home)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddSimulation(filepath.Join(dir, "run.yaml"), home); err != nil {
		t.Fatal(err)
	}
	if r := p.Simulation.Match("api.pay.test", "443", "GET", &url.URL{Path: "/v1/x"}, nil); r == nil || r.Stub != "specific" || string(r.Body) != "specific" {
		t.Fatalf("%+v", r)
	}
	if r := p.Simulation.Match("api.pay.test", "443", "GET", &url.URL{Path: "/v1/y"}, nil); r == nil || r.Stub != "general" {
		t.Fatalf("%+v", r)
	}
	if p.Sources[len(p.Sources)-1] != filepath.Join(dir, "run.yaml") {
		t.Fatalf("sources %v", p.Sources)
	}
	for _, bad := range []string{"allow: [x.test]\nsimulate:\n  - match: {host: a.test}\n", "simulate: []\n", ""} {
		write(t, filepath.Join(dir, "bad.yaml"), bad)
		if err := p.AddSimulation(filepath.Join(dir, "bad.yaml"), home); err == nil {
			t.Errorf("--simulate file loaded:\n%s", bad)
		}
	}
	if err := p.AddSimulation(filepath.Join(dir, "missing.yaml"), home); err == nil {
		t.Error("a missing --simulate file loaded")
	}
}
