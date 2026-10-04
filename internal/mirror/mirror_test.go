package mirror

import (
	"io"
	"net/http"
	"net/http/httptest"
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
}
