// Package mirror is a caching mirror of package registries, served at
// http://airbag.mirror/ through the egress proxy. Package managers in
// the sandbox point at it, so every package and version the agent pulls
// is in the effect log, immutable artifacts are cached across sessions,
// and nothing but a read leaves for the registries.
//
//	/go/...    the GOPROXY protocol, from proxy.golang.org (and its sumdb)
//	/npm/...   the npm registry; tarball URLs are rewritten to the mirror
//	/pypi/...  PyPI's simple index; file URLs are rewritten to the mirror
package mirror

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getjump/airbag/internal/effects"
)

const (
	Host = "airbag.mirror"
	Base = "http://" + Host
)

// Env points package managers at the mirror.
var Env = map[string]string{
	"GOPROXY":                    Base + "/go",
	"npm_config_registry":        Base + "/npm/",
	"YARN_NPM_REGISTRY_SERVER":   Base + "/npm",
	"YARN_UNSAFE_HTTP_WHITELIST": Host,
	"PIP_INDEX_URL":              Base + "/pypi/simple",
	"PIP_TRUSTED_HOST":           Host,
	"UV_DEFAULT_INDEX":           Base + "/pypi/simple",
	"UV_INSECURE_HOST":           Host,
}

type Mirror struct {
	Cache  string
	Log    *effects.Log
	Client *http.Client
}

func New(cache string, log *effects.Log) *Mirror {
	return &Mirror{Cache: cache, Log: log, Client: &http.Client{
		Timeout:   10 * time.Minute,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}}
}

func (m *Mirror) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// npm audit and friends send data out; the mirror only reads.
		http.Error(w, "airbag mirror is read-only", http.StatusNotFound)
		return
	}
	p := r.URL.EscapedPath()
	switch {
	case strings.HasPrefix(p, "/go/"):
		m.goproxy(w, r, strings.TrimPrefix(p, "/go"))
	case strings.HasPrefix(p, "/npm/"):
		m.npm(w, r, strings.TrimPrefix(p, "/npm"))
	case strings.HasPrefix(p, "/pypi/"):
		m.pypi(w, r, strings.TrimPrefix(p, "/pypi"))
	default:
		http.NotFound(w, r)
	}
}

func (m *Mirror) goproxy(w http.ResponseWriter, r *http.Request, p string) {
	if rest, ok := strings.CutPrefix(p, "/sumdb/sum.golang.org"); ok {
		if rest == "/supported" {
			w.WriteHeader(http.StatusOK)
			return
		}
		m.pass(w, r, "https://sum.golang.org"+rest, nil)
		return
	}
	up := "https://proxy.golang.org" + p
	mod, file, ok := strings.Cut(strings.TrimPrefix(p, "/"), "/@v/")
	if ok && (strings.HasSuffix(file, ".info") || strings.HasSuffix(file, ".mod") || strings.HasSuffix(file, ".zip")) {
		what := ""
		if strings.HasSuffix(file, ".zip") {
			what = "go " + unescapeGo(mod) + "@" + strings.TrimSuffix(file, ".zip")
		}
		m.cached(w, r, "go", up, what)
		return
	}
	m.pass(w, r, up, nil) // @v/list, @latest: they change
}

// unescapeGo undoes the module path case escaping (!a -> A).
func unescapeGo(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '!' && i+1 < len(s) {
			b.WriteByte(s[i+1] - 'a' + 'A')
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (m *Mirror) npm(w http.ResponseWriter, r *http.Request, p string) {
	up := "https://registry.npmjs.org" + p
	if strings.Contains(p, "/-/") && strings.HasSuffix(p, ".tgz") {
		pkg, file, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/-/")
		m.cached(w, r, "npm", up, "npm "+strings.ReplaceAll(pkg, "%2f", "/")+" "+file)
		return
	}
	m.pass(w, r, up, func(b []byte) []byte {
		return bytes.ReplaceAll(b, []byte("https://registry.npmjs.org/"), []byte(Base+"/npm/"))
	})
}

func (m *Mirror) pypi(w http.ResponseWriter, r *http.Request, p string) {
	if rest, ok := strings.CutPrefix(p, "/files/"); ok {
		m.cached(w, r, "pypi", "https://files.pythonhosted.org/"+rest, "pypi "+filepath.Base(rest))
		return
	}
	m.pass(w, r, "https://pypi.org"+p, func(b []byte) []byte {
		return bytes.ReplaceAll(b, []byte("https://files.pythonhosted.org/"), []byte(Base+"/pypi/files/"))
	})
}

// pass forwards a request whose answer may change, optionally rewriting
// the body.
func (m *Mirror) pass(w http.ResponseWriter, r *http.Request, url string, rewrite func([]byte) []byte) {
	req, _ := http.NewRequestWithContext(r.Context(), r.Method, url, nil)
	for _, h := range []string{"Accept", "Accept-Encoding", "User-Agent", "If-None-Match", "If-Modified-Since"} {
		if v := r.Header.Get(h); v != "" && !(h == "Accept-Encoding" && rewrite != nil) {
			req.Header.Set(h, v)
		}
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		http.Error(w, "airbag mirror: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "airbag mirror: "+err.Error(), http.StatusBadGateway)
		return
	}
	if rewrite != nil && resp.StatusCode == http.StatusOK {
		body = rewrite(body)
		resp.Header.Del("Content-Length")
		resp.Header.Del("Content-Encoding")
	}
	for _, h := range []string{"Content-Type", "Content-Encoding", "ETag", "Last-Modified", "Cache-Control"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// cached serves an immutable artifact from the cache, fetching it once.
func (m *Mirror) cached(w http.ResponseWriter, r *http.Request, registry, url, what string) {
	sum := sha256.Sum256([]byte(url))
	path := filepath.Join(m.Cache, registry, hex.EncodeToString(sum[:]))
	hit := true
	if _, err := os.Stat(path); err != nil {
		hit = false
		resp, err := m.Client.Get(url)
		if err != nil {
			http.Error(w, "airbag mirror: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			return
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmp, err := os.CreateTemp(filepath.Dir(path), ".dl-*")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := io.Copy(tmp, resp.Body); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			http.Error(w, "airbag mirror: "+err.Error(), http.StatusBadGateway)
			return
		}
		tmp.Close()
		if err := os.Rename(tmp.Name(), path); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if what != "" && m.Log != nil {
		reason := "fetched"
		if hit {
			reason = "cached"
		}
		m.Log.Add(effects.Effect{Kind: "pkg.fetch", Target: what, Verdict: "allow", Reason: reason})
	}
	http.ServeFile(w, r, path)
}
