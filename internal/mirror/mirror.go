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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
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
	// Tainted reports what secret the session read, if any. A tainted
	// session gets only what is already cached: no request it shapes
	// leaves the machine.
	Tainted func() string
	// Pinned: artifacts the real workspace's lock files name, which a
	// tainted session may still fetch (pins.go).
	Pinned Pins
}

func (m *Mirror) tainted() bool { return m.Tainted != nil && m.Tainted() != "" }

// refuse answers a request a tainted session may not send upstream.
func (m *Mirror) refuse(w http.ResponseWriter, url string) {
	if m.Log != nil {
		m.Log.Add(effects.Effect{Kind: "pkg.fetch", Target: url, Verdict: "deny", Reason: "secret-taint"})
	}
	http.Error(w, "airbag mirror: this session read a secret; only cached packages are served", http.StatusForbidden)
}

// registries are the hosts the mirror fetches from (proxy.Registries).
var registries = map[string]bool{
	"proxy.golang.org": true, "sum.golang.org": true,
	"registry.npmjs.org": true, "pypi.org": true, "files.pythonhosted.org": true,
}

// fromRegistry reports whether raw is an https URL on one of the
// registries, with no user info or port. Upstream URLs are a registry
// joined with a path from the sandbox, which must not change the host.
func fromRegistry(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.User == nil && u.Port() == "" && registries[u.Host]
}

// notRegistry answers a request whose upstream URL is not a registry's.
func (m *Mirror) notRegistry(w http.ResponseWriter, r *http.Request, url string) {
	if m.Log != nil {
		m.Log.Add(effects.Effect{Kind: "pkg.fetch", Target: url, Verdict: "deny", Reason: "not a registry"})
	}
	http.NotFound(w, r)
}

func (m *Mirror) cachePath(kind, url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(m.Cache, kind, hex.EncodeToString(sum[:]))
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
	// The slash ends the host: "/sumdb/sum.golang.org@other.example/"
	// is not a path on sum.golang.org.
	if rest, ok := strings.CutPrefix(p, "/sumdb/sum.golang.org/"); ok {
		if rest == "supported" {
			w.WriteHeader(http.StatusOK)
			return
		}
		m.pass(w, r, "https://sum.golang.org/"+rest, nil)
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
// The last good answer is kept, so a tainted session can still install
// what earlier sessions resolved.
func (m *Mirror) pass(w http.ResponseWriter, r *http.Request, url string, rewrite func([]byte) []byte) {
	if !fromRegistry(url) {
		m.notRegistry(w, r, url)
		return
	}
	meta := m.cachePath("meta", url)
	if m.tainted() {
		body, err := os.ReadFile(meta)
		if err != nil {
			m.refuse(w, url)
			return
		}
		if ct, err := os.ReadFile(meta + ".type"); err == nil {
			w.Header().Set("Content-Type", string(ct))
		}
		_, _ = w.Write(body)
		return
	}
	req, _ := http.NewRequestWithContext(r.Context(), r.Method, url, nil) //nolint:gosec // fromRegistry checked the host above
	// Accept-Encoding is left to the transport, so bodies arrive plain
	// and can be rewritten and kept.
	for _, h := range []string{"Accept", "User-Agent", "If-None-Match", "If-Modified-Since"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	resp, err := m.Client.Do(req) //nolint:gosec // fromRegistry checked the host above
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
	if resp.StatusCode == http.StatusOK && r.Method == http.MethodGet && resp.Header.Get("Content-Encoding") == "" {
		if writeAtomic(meta, body) == nil {
			_ = writeAtomic(meta+".type", []byte(resp.Header.Get("Content-Type")))
		}
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
	if !fromRegistry(url) {
		m.notRegistry(w, r, url)
		return
	}
	path := m.cachePath(registry, url)
	hit := true
	pinned := ""
	if _, err := os.Stat(path); err != nil {
		if m.tainted() {
			lock, ok := m.Pinned.Has(strings.ReplaceAll(url, "%2f", "/"))
			if !ok {
				m.refuse(w, url)
				return
			}
			pinned = lock
		}
		hit = false
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil) //nolint:gosec // fromRegistry checked the host above
		if err != nil {
			http.Error(w, "airbag mirror: "+err.Error(), http.StatusBadGateway)
			return
		}
		resp, err := m.Client.Do(req) //nolint:gosec // fromRegistry checked the host above
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
		_, err = io.Copy(tmp, resp.Body)
		if cerr := tmp.Close(); err == nil {
			err = cerr // a short write can show only here, and the cache keeps what it gets
		}
		if err != nil {
			_ = os.Remove(tmp.Name())
			http.Error(w, "airbag mirror: "+err.Error(), http.StatusBadGateway)
			return
		}
		if err := os.Rename(tmp.Name(), path); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if what != "" && m.Log != nil {
		reason := "fetched"
		if hit {
			reason = "cached"
		} else if pinned != "" {
			reason = "fetched after the secret read: pinned by " + pinned
		}
		m.Log.Add(effects.Effect{Kind: "pkg.fetch", Target: what, Verdict: "allow", Reason: reason})
	}
	http.ServeFile(w, r, path)
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dl-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
