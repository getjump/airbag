package secrets

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/creds"
	"github.com/getjump/airbag/internal/policy"
)

func TestWorth(t *testing.T) {
	yes := []string{
		"sk-live-4fG7xQ2mZ9",                          // a key with a prefix
		"ghp_e2eRealToken0123456789abcdefABCDEF",      // GitHub's shape
		"9f86d081884c7d659a2feaa0c55ad015",            // hex
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",    // base64
		"550e8400-e29b-41d4-a716-446655440000",        // a UUID
		"Pa55w0rd2024",                                // a password, just long enough
		"https://hooks.example.com/T0123ABCD/x9KdQ2z", // a URL whose path is the secret
	}
	no := []string{
		"true", "3000", "production", "localhost", "localhost:5432", "us-east-1",
		"my-bucket-2024", "http://localhost:3000", "https://api.example.com/v1",
		"node:18-alpine3.17", "2024-01-01T00:00:00Z", "admin@example.com",
		"correcthorsebatterystaple", "12345678901234567890", "MyApplicationName",
		"/nix/store/0a1b2c3d4e5f6a7b8c9d-pkg", "sk-short-a1B2", "has a space 4fG7xQ2mZ9",
	}
	for _, v := range yes {
		if !Worth(v) {
			t.Errorf("Worth(%q) = false, want true", v)
		}
	}
	for _, v := range no {
		if Worth(v) {
			t.Errorf("Worth(%q) = true, want false", v)
		}
	}
}

func TestParseDotenv(t *testing.T) {
	src := "# comment\n" +
		"export API_TOKEN=sk-live-4fG7xQ2mZ9\n" +
		"PORT=3000 # the port\n" +
		"QUOTED=\"a b\\\"c\\nd\"\n" +
		"SINGLE='lit\\n eral'\n" +
		"MULTI=\"-----BEGIN KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEF\n-----END KEY-----\"\n" +
		"  SPACED = value \r\n" +
		"not a line\n" +
		"EMPTY=\n" +
		"OPEN=\"unterminated\n"
	got := ParseDotenv([]byte(src))
	want := []struct{ k, v string }{
		{"API_TOKEN", "sk-live-4fG7xQ2mZ9"}, {"PORT", "3000"}, {"QUOTED", "a b\"c\nd"},
		{"SINGLE", `lit\n eral`}, {"MULTI", "-----BEGIN KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEF\n-----END KEY-----"},
		{"SPACED", "value"}, {"EMPTY", ""}, {"OPEN", "unterminated"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	for i, w := range want {
		if got[i].Key != w.k || got[i].Value != w.v {
			t.Errorf("entry %d: %q=%q, want %q=%q", i, got[i].Key, got[i].Value, w.k, w.v)
		}
	}
	// The offsets point at the value as written.
	if e := got[0]; src[e.Start:e.End] != "sk-live-4fG7xQ2mZ9" {
		t.Errorf("offsets of API_TOKEN: %q", src[e.Start:e.End])
	}
	if e := got[2]; src[e.Start:e.End] != `a b\"c\nd` {
		t.Errorf("offsets of QUOTED: %q", src[e.Start:e.End])
	}
}

func TestFromFiles(t *testing.T) {
	ws := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(ws, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".env", "API_TOKEN=sk-live-4fG7xQ2mZ9\nPORT=3000\nDB_HOST=localhost:5432\n"+
		"DATABASE_URL=postgres://app:Xk29dk3Lq9vA@db:5432/app\nNODE_ENV=production\n")
	write("apps/web/.env.local", "WEB_SECRET=\"Web9Secret7value3X\"\n")
	write(".env.example", "API_TOKEN=sk-live-4fG7xQ2mZ9example\n") // a template, not a secret file
	write("deploy.pem", "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAAS\nshort\n-----END PRIVATE KEY-----\n")
	write(".npmrc", "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_aB3dE5gH7jK9mN1p\n")
	got := map[string][]string{}
	for _, v := range FromFiles(ws) {
		got[v.Name] = append(got[v.Name], v.Value)
	}
	want := map[string][]string{
		".env#API_TOKEN":                 {"sk-live-4fG7xQ2mZ9"},
		".env#DATABASE_URL":              {"Xk29dk3Lq9vA"},
		"apps/web/.env.local#WEB_SECRET": {"Web9Secret7value3X"},
		"deploy.pem":                     {"-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAAS\nshort\n-----END PRIVATE KEY-----"},
		"deploy.pem:2":                   {"MIIBVgIBADANBgkqhkiG9w0BAQEFAAS"},
		".npmrc":                         {"registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_aB3dE5gH7jK9mN1p"},
		".npmrc:2":                       {"npm_aB3dE5gH7jK9mN1p"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FromFiles:\n got %q\nwant %q", got, want)
	}
}

func TestRegistry(t *testing.T) {
	r := New(Value{".env#A", "sk-live-4fG7xQ2mZ9"}, Value{"other#A", "sk-live-4fG7xQ2mZ9"}, Value{".env#B", "Web9Secret7value3X"})
	if r.Len() != 2 || !reflect.DeepEqual(r.Names(), []string{".env#A", ".env#B"}) {
		t.Fatalf("registry %+v", r.Values())
	}
	if got := r.Found([]byte("x Web9Secret7value3X y")); !reflect.DeepEqual(got, []string{".env#B"}) {
		t.Fatalf("Found = %v", got)
	}
	if got := Marked("secret x", "abc"); got != nil {
		t.Fatalf("a short marked value was registered: %v", got)
	}
	if got := Marked("secret x", "hunter2"); len(got) != 1 {
		t.Fatalf("a marked value was not registered whatever Worth says: %v", got)
	}
}

func TestLoadAndForSession(t *testing.T) {
	ws, home := t.TempDir(), t.TempDir()
	_ = os.WriteFile(filepath.Join(ws, ".env"), []byte("A=sk-live-4fG7xQ2mZ9\n"), 0o600)
	cfg := filepath.Join(home, ".config", "airbag", "airbag.yaml")
	_ = os.MkdirAll(filepath.Dir(cfg), 0o755)
	t.Setenv("E2E_PASSWORD", "hunter2")
	_ = os.WriteFile(cfg, []byte("secrets:\n  - name: db\n    source: env:E2E_PASSWORD\n  - name: vault\n    source: command:echo Vault7Value9Here3x\n"), 0o644)
	pol, err := policy.Load(ws, home)
	if err != nil {
		t.Fatal(err)
	}
	var warn strings.Builder
	live := creds.Set{{Name: "gh", Value: "ghp_e2eRealToken0123456789abcdefABCDEF"}}
	s := ForSession(ws, home, pol, live, &warn)
	if want := []string{".env#A", "credential gh", "secret db", "secret vault"}; !reflect.DeepEqual(s.Names(), want) {
		t.Errorf("ForSession names %v, want %v (%s)", s.Names(), want, warn.String())
	}
	// Review does not run commands again.
	if want := []string{".env#A", "secret db"}; !reflect.DeepEqual(Load(ws, home).Names(), want) {
		t.Errorf("Load names %v, want %v", Load(ws, home).Names(), want)
	}
	// A repository cannot mark secrets: a source may run a command.
	_ = os.WriteFile(filepath.Join(ws, "airbag.yaml"), []byte("secrets:\n  - name: x\n    source: command:id\n"), 0o644)
	if _, err := policy.Load(ws, home); err == nil || !strings.Contains(err.Error(), "secrets can only be set") {
		t.Errorf("a repository's secrets were accepted: %v", err)
	}
}
