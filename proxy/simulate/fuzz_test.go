package simulate

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/getjump/airbag/creds"
)

// webAllows is the allowlist's reading of a host entry on a web port,
// written out again here rather than imported from the proxy, which
// imports this package: exact, or a wildcard on a dot boundary, after
// the same spelling rules (creds.CanonHost).
func webAllows(entry, host string) bool {
	host = creds.CanonHost(host)
	if !creds.IsName(host) {
		return false
	}
	entry = creds.CanonHost(entry)
	return entry == host || (strings.HasPrefix(entry, "*.") && strings.HasSuffix(host, entry[1:]))
}

// globRef is a second, naive reading of the glob syntax: * matches any
// run of bytes without a /, when sep, ** any run at all.
func globRef(p, s string, sep bool) bool {
	if p == "" {
		return s == ""
	}
	if strings.HasPrefix(p, "**") {
		for i := 0; i <= len(s); i++ {
			if globRef(p[2:], s[i:], sep) {
				return true
			}
		}
		return false
	}
	if p[0] == '*' {
		for i := 0; i <= len(s); i++ {
			if globRef(p[1:], s[i:], sep) {
				return true
			}
			if i < len(s) && sep && s[i] == '/' {
				return false
			}
		}
		return false
	}
	return s != "" && p[0] == s[0] && globRef(p[1:], s[1:], sep)
}

// The matcher must answer for a host every spelling the allowlist would
// take for it, or a request in another spelling would go past the stub
// to the real host; and a stub must answer only requests on the host
// it names and a path its glob, read independently, matches.
func FuzzMatch(f *testing.F) {
	for _, s := range [][4]string{
		{"api.pay.test", "/v1/*", "API.pay.test.", "/v1/x"},
		{"*.pay.test", "/v1/**", "a.b.pay.test", "/v1/x/y"},
		{"*.pay.test", "/*/charges", "pay.test", "/v1/charges"},
		{"api.pay.test", "", "api.pay.test", "/"},
		{"api.pay.test", "/a*b*c", "api.pay.test", "/aXbYc"},
		{"api.pay.test", "/**/x", "api.pay.test", "//x"},
	} {
		f.Add(s[0], s[1], s[2], s[3], "443")
	}
	f.Fuzz(func(t *testing.T, host, path, reqHost, reqPath, port string) {
		if len(path) > 64 || len(reqPath) > 64 {
			return // the naive reference is exponential
		}
		set, err := Compile([]Stub{{Name: "s", Match: Match{Host: host, Path: path}}})
		if err != nil {
			return
		}
		cp := creds.CanonPort(port)
		web := cp == "80" || cp == "443"
		pattern := set.Hosts()[0]
		if web && !strings.Contains(pattern, ":") && webAllows(pattern, reqHost) && !set.Covers(reqHost, port) {
			t.Fatalf("stub host %q: the allowlist takes %q, Covers does not", host, reqHost)
		}
		u := &url.URL{Path: reqPath}
		r := set.Match(reqHost, port, http.MethodGet, u, nil)
		if r != nil && !set.Covers(reqHost, port) {
			t.Fatalf("matched %q:%s, which the set does not cover", reqHost, port)
		}
		if !set.Covers(reqHost, port) {
			return
		}
		p := reqPath
		if p == "" {
			p = "/"
		}
		if want := path == "" || globRef(path, p, true); (r != nil) != want {
			t.Fatalf("path %q against glob %q: matched %v, want %v", p, path, r != nil, want)
		}
	})
}

// Whatever a stub says, what compiles answers within the bounds: a
// status a client takes as final, a body under MaxBody, a delay under
// MaxDelay, response headers that cannot change the framing, and a
// host that is a name; a request on another host gets nothing.
func FuzzCompile(f *testing.F) {
	f.Add("charge", "POST", "api.pay.test", "/v1/charges", "currency", "usd", "Content-Type", "application/json", 200, `{"ok":true}`, "1s")
	f.Add("", "", "*.pay.test:8443", "/**", "", "", "", "", 503, "", "")
	f.Add("x", "get", "a.test", "/*", "k", "*", "Content-Length", "1", 204, "", "-1s")
	f.Fuzz(func(t *testing.T, name, method, host, path, qk, qv, hk, hv string, status int, body, delay string) {
		m := Match{Method: method, Host: host, Path: path}
		if qk != "" {
			m.Query = map[string]string{qk: qv}
		}
		r := Respond{Status: status, Body: body, Delay: delay}
		if hk != "" {
			r.Headers = map[string]string{hk: hv}
		}
		set, err := Compile([]Stub{{Name: name, Match: m, Respond: r}})
		if err != nil {
			return
		}
		st := set.stubs[0]
		resp := st.resp
		if resp.Status < 200 || resp.Status > 599 || len(resp.Body) > MaxBody || resp.Delay < 0 || resp.Delay > MaxDelay {
			t.Fatalf("out of bounds: %+v", resp)
		}
		for k, vs := range resp.Header {
			if framing[http.CanonicalHeaderKey(k)] {
				t.Fatalf("framing header %s kept", k)
			}
			for _, v := range vs {
				if strings.ContainsAny(v, "\r\n") {
					t.Fatalf("header %s holds a line break", k)
				}
			}
		}
		h := strings.TrimPrefix(st.host, "*.")
		if h == "" || strings.ContainsAny(h, "*[]:/ ") || h != strings.ToLower(h) {
			t.Fatalf("host pattern %q", st.host)
		}
		other := "other-" + strings.ReplaceAll(h, ".", "-") + ".invalid" // under no wildcard and equal to no name a stub can hold
		if set.Covers(other, "443") || set.Match(other, "443", "GET", &url.URL{Path: "/"}, nil) != nil {
			t.Fatalf("stub on %q answers %q", host, other)
		}
	})
}
