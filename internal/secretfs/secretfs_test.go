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
