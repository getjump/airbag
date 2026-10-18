// Package simulate answers HTTP requests from stubs the user wrote, in
// place of the hosts they name. A Set is compiled from Stubs; airbag's
// proxy asks it whether a host is simulated and which stub answers a
// request. It does no I/O: the caller reads body files, serves the
// answer and logs it.
//
// A host that any stub names is simulated as a whole: each request to
// it gets the first stub that matches, and a request that none matches
// is refused. Nothing is ever sent to a simulated host, so a stub can
// only narrow what a session reaches, never widen it.
package simulate

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/getjump/airbag/creds"
)

// Kind is the effect kind airbag logs for a request to a simulated
// host: allowed, with the stub's name as the reason, when a stub
// answered it; denied when none matched, or its TLS failed.
const Kind = "net.simulated"

// Stub is one simulated answer: the requests it matches and what they
// get.
type Stub struct {
	Name    string  `yaml:"name" json:"name"`
	Match   Match   `yaml:"match" json:"match"`
	Respond Respond `yaml:"respond" json:"respond"`
}

// Match selects requests. Host is required; every other field left
// empty matches anything.
type Match struct {
	// Method is an HTTP method (GET, POST); empty is any.
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
	// Host is a name ("api.example.com") or a wildcard over the names
	// under one ("*.example.com"), optionally with a port. Without one it
	// covers ports 80 and 443, as the allowlist does.
	Host string `yaml:"host" json:"host"`
	// Path is exact, or a glob: * matches within one path segment, **
	// across segments. Empty is any path.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// Query and Headers name values the request must have: each key
	// needs a value that matches its glob (* matches anything).
	Query   map[string]string `yaml:"query,omitempty" json:"query,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// Respond is the answer. BodyFile is read by whoever loads the stubs
// (airbag's policy loader), which puts the bytes in Body: Compile
// refuses a BodyFile still set, so no file is read here.
type Respond struct {
	Status   int               `yaml:"status,omitempty" json:"status,omitempty"` // 200 when 0
	Headers  map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body     string            `yaml:"body,omitempty" json:"body,omitempty"`
	BodyFile string            `yaml:"body_file,omitempty" json:"body_file,omitempty"`
	// Delay before the answer, as Go writes durations ("1.5s").
	Delay string `yaml:"delay,omitempty" json:"delay,omitempty"`
}

// Bounds on what a Set holds. The answers live in airbag's memory on
// the host, and a request waits through its delay with a connection
// open, so both are capped.
const (
	MaxStubs     = 1024
	MaxBody      = 4 << 20  // one answer's body
	MaxTotalBody = 32 << 20 // all of them
	// MaxDelay stays under the proxy's 15-minute idle limit, which would
	// otherwise close a connection waiting through a longer delay.
	MaxDelay = 10 * time.Minute
	// MaxRequestBody is how much of a request's body the proxy reads
	// before it answers; a longer body is not read, and the connection
	// closes after the answer.
	MaxRequestBody = 1 << 20

	maxName    = 64
	maxPattern = 1024
	maxPairs   = 32
	maxHeaders = 64
)

// Response is what a stub answers. It is shared by every request the
// stub matches: callers copy what they change.
type Response struct {
	Stub   string
	Status int
	Header http.Header
	Body   []byte
	Delay  time.Duration
}

// Set is a compiled list of stubs, tried in order. A nil Set simulates
// nothing.
type Set struct {
	stubs []stub
	hosts []string
}

type stub struct {
	method  string
	host    string // a canonical name, or "*." and one
	port    string // "" for 80 and 443
	path    *regexp.Regexp
	query   []pair
	headers []pair
	resp    *Response
}

type pair struct {
	key string
	re  *regexp.Regexp
}

// Compile checks stubs and compiles them; any problem is an error, not
// a stub left out. A stub's name defaults to "stub#N", its position.
func Compile(stubs []Stub) (*Set, error) {
	if len(stubs) > MaxStubs {
		return nil, fmt.Errorf("%d stubs; at most %d", len(stubs), MaxStubs)
	}
	s := &Set{}
	names := map[string]bool{}
	total := 0
	for i, st := range stubs {
		name := st.Name
		if name == "" {
			name = "stub#" + strconv.Itoa(i+1)
		}
		if err := checkName(name); err != nil {
			return nil, fmt.Errorf("stub %d: %w", i+1, err)
		}
		if names[name] {
			return nil, fmt.Errorf("stub %s: the name is used twice", name)
		}
		names[name] = true
		c, err := compile(name, st)
		if err != nil {
			return nil, fmt.Errorf("stub %s: %w", name, err)
		}
		if total += len(c.resp.Body); total > MaxTotalBody {
			return nil, fmt.Errorf("stub %s: the bodies come to more than %d bytes", name, MaxTotalBody)
		}
		s.stubs = append(s.stubs, c)
		h := c.host
		if c.port != "" {
			h += ":" + c.port
		}
		if !slices.Contains(s.hosts, h) {
			s.hosts = append(s.hosts, h)
		}
	}
	return s, nil
}

func compile(name string, st Stub) (stub, error) {
	m, r := st.Match, st.Respond
	host, port, err := hostPattern(m.Host)
	if err != nil {
		return stub{}, fmt.Errorf("host %q: %w", clip(m.Host), err)
	}
	c := stub{host: host, port: port}
	if m.Method != "" {
		c.method = strings.ToUpper(m.Method)
		if !isToken(c.method) || len(c.method) > 32 {
			return stub{}, fmt.Errorf("method %q is not an HTTP method", clip(m.Method))
		}
		if c.method == http.MethodConnect {
			return stub{}, errors.New("method CONNECT opens a tunnel, which a stub does not answer")
		}
	}
	if m.Path != "" {
		if !strings.HasPrefix(m.Path, "/") || strings.ContainsAny(m.Path, "?#") {
			return stub{}, fmt.Errorf("path %q must start with / and hold no query (match it with query:)", clip(m.Path))
		}
		if c.path, err = glob(m.Path, true); err != nil {
			return stub{}, fmt.Errorf("path %q: %w", clip(m.Path), err)
		}
	}
	if c.query, err = pairs(m.Query, false); err != nil {
		return stub{}, fmt.Errorf("query: %w", err)
	}
	if c.headers, err = pairs(m.Headers, true); err != nil {
		return stub{}, fmt.Errorf("headers: %w", err)
	}
	resp := &Response{Stub: name, Status: r.Status, Header: http.Header{}, Body: []byte(r.Body)}
	if resp.Status == 0 {
		resp.Status = http.StatusOK
	}
	// A 1xx answer is not a final one: the client would wait for another.
	if resp.Status < 200 || resp.Status > 599 {
		return stub{}, fmt.Errorf("status %d: want 200 to 599", r.Status)
	}
	if r.BodyFile != "" {
		return stub{}, fmt.Errorf("body_file %q was not read; the loader puts its bytes in body", clip(r.BodyFile))
	}
	if len(resp.Body) > MaxBody {
		return stub{}, fmt.Errorf("body of %d bytes; at most %d", len(resp.Body), MaxBody)
	}
	if len(resp.Body) > 0 && (resp.Status == http.StatusNoContent || resp.Status == http.StatusNotModified) {
		return stub{}, fmt.Errorf("status %d has no body", resp.Status)
	}
	if len(r.Headers) > maxHeaders {
		return stub{}, fmt.Errorf("%d response headers; at most %d", len(r.Headers), maxHeaders)
	}
	for k, v := range r.Headers {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		switch {
		case !isToken(k):
			return stub{}, fmt.Errorf("response header %q is not a header name", clip(k))
		case framing[ck]:
			// airbag frames the answer itself; these would change where it
			// ends, or what the connection does after it.
			return stub{}, fmt.Errorf("response header %s is set by airbag", ck)
		case !headerValue(v):
			return stub{}, fmt.Errorf("response header %s holds a control character", ck)
		case resp.Header[ck] != nil:
			return stub{}, fmt.Errorf("response header %s twice", ck)
		}
		resp.Header[ck] = []string{v}
	}
	if r.Delay != "" {
		d, err := time.ParseDuration(r.Delay)
		if err != nil || d < 0 || d > MaxDelay {
			return stub{}, fmt.Errorf("delay %q: want a duration from 0 to %s", clip(r.Delay), MaxDelay)
		}
		resp.Delay = d
	}
	c.resp = resp
	return c, nil
}

var framing = map[string]bool{
	"Content-Length": true, "Transfer-Encoding": true, "Connection": true, "Keep-Alive": true,
	"Upgrade": true, "Proxy-Connection": true, "Proxy-Authenticate": true, "Trailer": true, "Te": true,
}

// hostPattern spells a stub's host as the proxy spells the hosts it
// sees (creds.CanonHost), or says why it cannot be one: names only, as
// an IP address would need the session CA to vouch for addresses too.
func hostPattern(h string) (host, port string, err error) {
	if h == "" {
		return "", "", errors.New("a stub names its host")
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h, port = h[:i], h[i+1:]
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", "", errors.New("the port is not a port number")
		}
		port = strconv.Itoa(n)
	}
	wild := strings.HasPrefix(h, "*.")
	name := creds.CanonHost(strings.TrimPrefix(h, "*."))
	if _, err := netip.ParseAddr(name); err == nil || strings.ContainsAny(name, "[]:") {
		return "", "", errors.New("a stub names a host by name, not by address")
	}
	if len(name) > 253 {
		return "", "", errors.New("the name is too long")
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", "", errors.New("the name has an empty or overlong label")
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", "", errors.New("a name holds letters, digits, - and _ (an international name in its xn-- form; * only as the first label)")
			}
		}
	}
	if wild && len(labels) < 2 {
		// *.com would take over every name under a top-level domain, the
		// agent's own model API among them.
		return "", "", errors.New("a wildcard covers the names under at least two labels (*.example.com)")
	}
	if name == "airbag.mirror" {
		return "", "", errors.New("airbag.mirror is airbag's package mirror")
	}
	if wild {
		name = "*." + name
	}
	return name, port, nil
}

func pairs(m map[string]string, header bool) ([]pair, error) {
	if len(m) > maxPairs {
		return nil, fmt.Errorf("%d entries; at most %d", len(m), maxPairs)
	}
	var out []pair
	for k, v := range m {
		key := k
		if header {
			if !isToken(k) {
				return nil, fmt.Errorf("%q is not a header name", clip(k))
			}
			key = textproto.CanonicalMIMEHeaderKey(k)
			if key == "Host" {
				return nil, errors.New("the Host header is matched by match.host")
			}
		} else if k == "" || len(k) > maxPattern || !text(k) {
			return nil, fmt.Errorf("query key %q", clip(k))
		}
		if slices.ContainsFunc(out, func(p pair) bool { return p.key == key }) {
			return nil, fmt.Errorf("%s twice", key)
		}
		re, err := glob(v, false)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		out = append(out, pair{key: key, re: re})
	}
	// Map order is random; the order pairs are checked in has no effect on
	// the answer, but a stable one keeps errors and tests repeatable.
	slices.SortFunc(out, func(a, b pair) int { return strings.Compare(a.key, b.key) })
	return out, nil
}

// glob compiles a pattern where * matches any run of characters (within
// one path segment, for a path) and ** any run at all. Everything else
// is literal. RE2 runs in time linear in the input, whatever the
// pattern, so a request cannot make the host spin.
func glob(p string, path bool) (*regexp.Regexp, error) {
	if len(p) > maxPattern {
		return nil, fmt.Errorf("pattern of %d bytes; at most %d", len(p), maxPattern)
	}
	if !text(p) {
		return nil, errors.New("the pattern holds a control character or is not UTF-8")
	}
	var b strings.Builder
	b.WriteString(`^(?s:`)
	for i := 0; i < len(p); {
		switch {
		case strings.HasPrefix(p[i:], "**"):
			b.WriteString(`.*`)
			i += 2
		case p[i] == '*' && path:
			b.WriteString(`[^/]*`)
			i++
		case p[i] == '*':
			b.WriteString(`.*`)
			i++
		default:
			j := strings.IndexByte(p[i:], '*')
			if j < 0 {
				j = len(p) - i
			}
			b.WriteString(regexp.QuoteMeta(p[i : i+j]))
			i += j
		}
	}
	b.WriteString(`)$`)
	return regexp.Compile(b.String())
}

// Covers reports whether a stub names host on port: the proxy then
// answers every request to it, and sends none on. host is spelled as
// the proxy spells it; another spelling of the same name is covered
// too, as the allowlist would allow it.
func (s *Set) Covers(host, port string) bool {
	if s == nil {
		return false
	}
	host, port = creds.CanonHost(host), creds.CanonPort(port)
	for i := range s.stubs {
		if s.stubs[i].covers(host, port) {
			return true
		}
	}
	return false
}

func (c *stub) covers(host, port string) bool {
	if !creds.IsName(host) {
		return false
	}
	if c.port == "" {
		if port != "80" && port != "443" {
			return false
		}
	} else if port != c.port {
		return false
	}
	// As the allowlist reads a wildcard, so that every spelling it would
	// let through to the host is answered here instead.
	if suffix, ok := strings.CutPrefix(c.host, "*"); ok {
		return strings.HasSuffix(host, suffix)
	}
	return host == c.host
}

// Match returns the answer of the first stub that matches the request,
// or nil: on a host Covers reports, nil means the request is refused.
func (s *Set) Match(host, port, method string, u *url.URL, h http.Header) *Response {
	if s == nil || u == nil {
		return nil
	}
	host, port = creds.CanonHost(host), creds.CanonPort(port)
	p := u.Path
	if p == "" {
		p = "/"
	}
	var q url.Values
	var qerr error
	for i := range s.stubs {
		c := &s.stubs[i]
		if !c.covers(host, port) || (c.method != "" && c.method != method) || (c.path != nil && !c.path.MatchString(p)) {
			continue
		}
		if len(c.query) > 0 && q == nil && qerr == nil {
			q, qerr = url.ParseQuery(u.RawQuery)
		}
		// A query that does not parse matches no stub that asks about it:
		// the request is refused, not answered by a guess.
		if len(c.query) > 0 && qerr != nil {
			continue
		}
		if anyMiss(c.query, func(k string) []string { return q[k] }) || anyMiss(c.headers, h.Values) {
			continue
		}
		return c.resp
	}
	return nil
}

func anyMiss(ps []pair, values func(string) []string) bool {
	for _, p := range ps {
		if !slices.ContainsFunc(values(p.key), p.re.MatchString) {
			return true
		}
	}
	return false
}

// Hosts lists the hosts the stubs name, each once, in the order they
// first appear ("api.example.com", "*.example.com", "api.example.com:8443"):
// the names the session CA vouches for.
func (s *Set) Hosts() []string {
	if s == nil {
		return nil
	}
	return slices.Clone(s.hosts)
}

// Len is the number of stubs.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.stubs)
}

func checkName(n string) error {
	if len(n) > maxName {
		return fmt.Errorf("name %q is longer than %d bytes", clip(n), maxName)
	}
	for i := 0; i < len(n); i++ {
		// Names go into the log and the review, which print them as they
		// are: printable ASCII keeps them from steering a terminal.
		if n[i] <= ' ' || n[i] > '~' {
			return fmt.Errorf("name %q: printable ASCII without spaces", clip(n))
		}
	}
	return nil
}

// isToken reports whether s is an HTTP token (RFC 9110), as a method
// or a header name must be.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

func headerValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

// text is valid UTF-8 without control characters.
func text(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
