package mirror

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRegistry struct{ calls []string }

func (f *fakeRegistry) RoundTrip(r *http.Request) (*http.Response, error) {
	f.calls = append(f.calls, r.URL.String())
	body := `{"versions":{"1.3.0":{"dist":{"tarball":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}}`
	ct := "application/json"
	if strings.HasSuffix(r.URL.Path, ".tgz") {
		body, ct = "TARBALL", "application/octet-stream"
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {ct}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func TestTaintedServesOnlyCache(t *testing.T) {
	reg := &fakeRegistry{}
	m := New(t.TempDir(), nil)
	m.Client = &http.Client{Transport: reg}
	tainted := ""
	m.Tainted = func() string { return tainted }
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		m.ServeHTTP(w, httptest.NewRequest("GET", Base+path, nil))
		return w
	}

	if w := get("/npm/left-pad"); w.Code != 200 || !strings.Contains(w.Body.String(), Base+"/npm/left-pad/-/") {
		t.Fatalf("metadata: %d %s", w.Code, w.Body)
	}
	if w := get("/npm/left-pad/-/left-pad-1.3.0.tgz"); w.Code != 200 || w.Body.String() != "TARBALL" {
		t.Fatalf("tarball: %d %s", w.Code, w.Body)
	}
	before := len(reg.calls)

	tainted = ".env"
	w := get("/npm/left-pad")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "left-pad-1.3.0.tgz") || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("cached metadata after taint: %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body)
	}
	if w := get("/npm/left-pad/-/left-pad-1.3.0.tgz"); w.Code != 200 {
		t.Fatalf("cached tarball after taint: %d", w.Code)
	}
	for _, p := range []string{"/npm/other", "/npm/other/-/other-1.0.0.tgz", "/go/example.com/m/@v/list", "/pypi/simple/six/"} {
		if w := get(p); w.Code != http.StatusForbidden {
			t.Errorf("%s after taint: %d, want 403", p, w.Code)
		}
	}
	if len(reg.calls) != before {
		t.Fatalf("a tainted session reached the registry: %v", reg.calls[before:])
	}

	// What the real workspace's lock file pins is fetched even now.
	m.Pinned = Pins{"https://registry.npmjs.org/@scope/pinned/-/pinned-2.0.0.tgz": "package-lock.json"}
	if w := get("/npm/@scope/pinned/-/pinned-2.0.0.tgz"); w.Code != 200 || w.Body.String() != "TARBALL" {
		t.Fatalf("pinned tarball after taint: %d %s", w.Code, w.Body)
	}
	if w := get("/npm/@scope/pinned/-/pinned-2.0.1.tgz"); w.Code != http.StatusForbidden {
		t.Fatalf("an unpinned version after taint: %d", w.Code)
	}
}

func TestFindPins(t *testing.T) {
	ws := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(ws, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("web/package-lock.json", `{"lockfileVersion":3,"packages":{"":{},
		"node_modules/left-pad":{"resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-x"},
		"node_modules/@s/p":{"resolved":"https://registry.npmjs.org/@s/p/-/p-1.0.0.tgz"}}}`)
	write("old/package-lock.json", `{"lockfileVersion":1,"dependencies":{"a":{"resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz",
		"dependencies":{"b":{"resolved":"https://registry.npmjs.org/b/-/b-2.0.0.tgz"}}}}}`)
	write("yarn.lock", `left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.1.tgz#abc"
`)
	write("go.sum", `github.com/BurntSushi/toml v1.4.0 h1:aaa=
github.com/BurntSushi/toml v1.4.0/go.mod h1:bbb=
`)
	write("py/uv.lock", `wheels = [{ url = "https://files.pythonhosted.org/packages/ab/six-1.16.0-py2.py3-none-any.whl", hash = "sha256:x" }]
`)
	write("node_modules/x/package-lock.json", `{"packages":{"node_modules/z":{"resolved":"https://registry.npmjs.org/z/-/z-9.tgz"}}}`)
	p := FindPins(ws)
	for _, want := range []string{
		"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
		"https://registry.npmjs.org/@s/p/-/p-1.0.0.tgz",
		"https://registry.npmjs.org/a/-/a-1.0.0.tgz",
		"https://registry.npmjs.org/b/-/b-2.0.0.tgz",
		"https://registry.npmjs.org/left-pad/-/left-pad-1.3.1.tgz",
		"https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0.zip",
		"https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0.mod",
		"https://files.pythonhosted.org/packages/ab/six-1.16.0-py2.py3-none-any.whl",
	} {
		if _, ok := p.Has(want); !ok {
			t.Errorf("not pinned: %s", want)
		}
	}
	if _, ok := p.Has("https://registry.npmjs.org/z/-/z-9.tgz"); ok {
		t.Error("a lock file inside node_modules counted")
	}
}

// A path from the sandbox never changes the host the mirror fetches
// from: "@host" or ".host" right after a registry's name would.
func TestFetchesOnlyFromRegistries(t *testing.T) {
	reg := &fakeRegistry{}
	m := New(t.TempDir(), nil)
	m.Client = &http.Client{Transport: reg}
	for _, p := range []string{
		"/go/sumdb/sum.golang.org@example.com/lookup/x",
		"/go/sumdb/sum.golang.org.example.com/lookup/x",
		"/go/sumdb/sum.golang.org:8443/lookup/x",
		"/go/sumdb/sum.golang.org/lookup/x@v1.0.0",
		"/npm/left-pad",
	} {
		m.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", Base+p, nil))
	}
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest("GET", Base+"/go/sumdb/sum.golang.org/supported", nil))
	if w.Code != http.StatusOK {
		t.Errorf("supported: %d", w.Code)
	}
	var sumdb int
	for _, c := range reg.calls {
		u, err := url.Parse(c)
		if err != nil || u.User != nil || !registries[u.Host] {
			t.Errorf("fetched from %s", c)
		}
		if u.Host == "sum.golang.org" {
			sumdb++
		}
	}
	if sumdb != 1 || len(reg.calls) != 5 {
		t.Errorf("upstream calls: %v", reg.calls)
	}
	for _, raw := range []string{"https://sum.golang.org@example.com/x", "https://sum.golang.org.example.com/x", "http://pypi.org/simple/", "https://pypi.org:8443/simple/"} {
		if fromRegistry(raw) {
			t.Errorf("fromRegistry(%q) = true", raw)
		}
	}
}
