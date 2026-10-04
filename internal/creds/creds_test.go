package creds

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlaceholderShape(t *testing.T) {
	real := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	p := Placeholder(real)
	if len(p) != len(real) || !strings.HasPrefix(p, "ghp_") || p == real {
		t.Fatalf("placeholder %q", p)
	}
	if p := Placeholder("short"); len(p) < 16 || strings.HasPrefix(p, "short") {
		t.Fatalf("short value: %q", p)
	}
}

func TestValidate(t *testing.T) {
	ok := Binding{Name: "github", Hosts: []string{"api.github.com", "*.githubusercontent.com", "git.corp:8443"}, Source: "command:gh auth token", Env: []string{"GH_TOKEN"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, b := range []Binding{
		{Name: "x", Source: "env:X"},
		{Name: "x", Hosts: []string{"a b"}, Source: "env:X"},
		{Name: "x", Hosts: []string{"h"}, Source: "vault:x"},
		{Name: "x", Hosts: []string{"h"}, Source: "env:bad-name"},
		{Name: "X", Hosts: []string{"h"}, Source: "env:X"},
		{Name: "x", Hosts: []string{"h:abc"}, Source: "env:X"},
	} {
		if b.Validate() == nil {
			t.Errorf("accepted %+v", b)
		}
	}
}

func TestResolve(t *testing.T) {
	home := t.TempDir()
	_ = os.WriteFile(filepath.Join(home, "tok"), []byte("  file-token-value\n"), 0o600)
	t.Setenv("AIRBAG_TEST_TOKEN", "env-token-value")
	for src, want := range map[string]string{
		"env:AIRBAG_TEST_TOKEN":        "env-token-value",
		"file:~/tok":                   "file-token-value",
		"command:echo cmd-token-value": "cmd-token-value",
	} {
		if got, err := Resolve(src, home); err != nil || got != want {
			t.Errorf("%s: %q %v", src, got, err)
		}
	}
	if _, err := Resolve("env:AIRBAG_UNSET_X", home); err == nil {
		t.Error("unset variable resolved")
	}
	if _, err := Resolve("command:printf a\\nb", home); err == nil {
		t.Error("multi-line value accepted")
	}
}

func TestForAndSubstitute(t *testing.T) {
	l := &Live{Name: "g", Hosts: []string{"api.github.com", "*.example.com", "git.corp:8443"}, Value: "realvalue-1234567890", Placeholder: "fakevalue-0987654321"}
	s := Set{l}
	for hp, want := range map[string]bool{
		"api.github.com:443": true, "API.GitHub.com.:443": true, "api.github.com:8443": false,
		"a.example.com:443": true, "example.com:443": false, "git.corp:8443": true, "git.corp:443": false, "evil.com:443": false,
	} {
		if got := s.For(hp) != nil; got != want {
			t.Errorf("For(%s) = %v", hp, got)
		}
	}
	h := http.Header{"Authorization": {"token " + l.Placeholder}, "X-Other": {"none"}}
	u, _ := url.Parse("https://api.github.com/x?access_token=" + l.Placeholder)
	if !l.Substitute(h, u) || h.Get("Authorization") != "token "+l.Value || !strings.Contains(u.RawQuery, l.Value) {
		t.Fatalf("not substituted: %v %s", h, u)
	}
	if l.Substitute(http.Header{"Authorization": {"Bearer other"}}, nil) {
		t.Fatal("substituted without the placeholder")
	}
}

// The value is masked even when a read splits it.
func TestMaskBodySplit(t *testing.T) {
	l := &Live{Value: "realvalue-1234567890", Placeholder: "fakevalue-0987654321"}
	src := "head " + l.Value + " middle " + l.Value + " tail"
	for _, chunk := range []int{1, 3, 7, 64} {
		r := l.MaskBody(io.NopCloser(&slow{data: []byte(src), n: chunk}))
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.ReplaceAll(src, l.Value, l.Placeholder); string(out) != want {
			t.Fatalf("chunk %d: %q", chunk, out)
		}
	}
}

type slow struct {
	data []byte
	n    int
}

func (s *slow) Read(p []byte) (int, error) {
	if len(s.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.data[:min(s.n, len(s.data))])
	s.data = s.data[n:]
	return n, nil
}

// A chunk that cannot hold the start of the value goes out at once.
func TestMaskBodyStreams(t *testing.T) {
	l := &Live{Value: "realvalue-1234567890", Placeholder: "fakevalue-0987654321"}
	pr, pw := io.Pipe()
	r := l.MaskBody(pr)
	go func() { _, _ = pw.Write([]byte("data: one\n\n")) }()
	buf := make([]byte, 64)
	n, err := r.Read(buf)
	if err != nil || string(buf[:n]) != "data: one\n\n" {
		t.Fatalf("event held back: %q %v", buf[:n], err)
	}
	_ = pw.Close()
}

// A binding and a request match when they name the same host and port
// in any spelling.
func TestForCanonical(t *testing.T) {
	s := Set{{Name: "v6", Hosts: []string{"[0:0::1]:0443"}}, {Name: "name", Hosts: []string{"API.Example."}}}
	for in, want := range map[string]string{
		"[::1]:443": "v6", "[0:0:0::1]:443": "v6", "api.example:443": "name", "API.EXAMPLE.:0443": "name", "api.example:8443": "",
	} {
		got := ""
		if l := s.For(in); l != nil {
			got = l.Name
		}
		if got != want {
			t.Errorf("For(%q) = %q, want %q", in, got, want)
		}
	}
}
