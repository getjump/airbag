package secretfs

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestIsSecret(t *testing.T) {
	yes := []string{".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", "server.pem", "tls.key", ".npmrc", ".pypirc", "credentials.json", "prod.tfvars", "secrets.tfvars.json"}
	no := []string{".env.example", ".env.sample", "id_rsa.pub", "main.go", "README.md", "env.ts", "key.go", "notes.txt"}
	for _, n := range yes {
		if !IsSecret(n) {
			t.Errorf("IsSecret(%q) = false, want true", n)
		}
	}
	for _, n := range no {
		if IsSecret(n) {
			t.Errorf("IsSecret(%q) = true, want false", n)
		}
	}
}

func TestOpenNested(t *testing.T) {
	ws := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(ws, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".env", "A=1")
	write("apps/web/.env", "B=2")
	write("deploy/prod.tfvars", "token=3")
	write(".env.example", "A=")
	write("node_modules/pkg/.env", "C=4") // skipped dir
	write("src/main.go", "package main")

	files := Open(ws)
	var got []string
	for _, f := range files {
		got = append(got, filepath.ToSlash(f.Rel))
		_ = f.F.Close()
	}
	sort.Strings(got)
	want := []string{".env", "apps/web/.env", "deploy/prod.tfvars"}
	if len(got) != len(want) {
		t.Fatalf("Open = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Open = %v, want %v", got, want)
		}
	}
}

// A workspace named through a link has its secret files found all the
// same: a walk does not enter a root that is a link.
func TestFindThroughLinkedRoot(t *testing.T) {
	real := t.TempDir()
	if err := os.MkdirAll(filepath.Join(real, "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{".env", "api/.env.local"} {
		if err := os.WriteFile(filepath.Join(real, rel), []byte("K=v\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(t.TempDir(), "ws")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got := Find(link)
	sort.Strings(got)
	if len(got) != 2 || got[0] != ".env" || got[1] != filepath.Join("api", ".env.local") {
		t.Fatalf("Find through a link: %v", got)
	}
	files := Open(link)
	for _, f := range files {
		_ = f.F.Close()
	}
	if len(files) != 2 {
		t.Fatalf("Open through a link opened %d files", len(files))
	}
}
