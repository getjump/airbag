// Package creds lets the agent use a credential without holding it.
// The agent gets a placeholder of the same shape; airbag's proxy
// terminates TLS for the hosts the credential is bound to and puts the
// real value in place of the placeholder on the way out, and the
// placeholder back in place of the value on the way in. The value
// stays in the airbag process on the host.
//
// Bindings come only from the user's own configuration: a repository
// must not decide which hosts receive the user's tokens.
package creds

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Binding is one credential in ~/.config/airbag/airbag.yaml:
//
//	credentials:
//	  - name: github
//	    hosts: [api.github.com, uploads.github.com]
//	    source: command:gh auth token     # or env:GH_TOKEN, file:~/.config/x/token
//	    env: [GH_TOKEN]                   # the agent sees the placeholder here
type Binding struct {
	Name   string   `yaml:"name"`
	Hosts  []string `yaml:"hosts"`
	Source string   `yaml:"source"`
	Env    []string `yaml:"env"`
}

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	envRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	hostRe = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
)

func (b Binding) Validate() error {
	if !nameRe.MatchString(b.Name) {
		return fmt.Errorf("name %q: lowercase letters, digits, - and _", b.Name)
	}
	if len(b.Hosts) == 0 {
		return fmt.Errorf("%s: no hosts: a credential goes only to the hosts it names", b.Name)
	}
	for _, h := range b.Hosts {
		host, port := SplitHost(h)
		if !hostRe.MatchString(host) && net.ParseIP(host) == nil {
			return fmt.Errorf("%s: host %q", b.Name, h)
		}
		if port == "" {
			return fmt.Errorf("%s: port in %q", b.Name, h)
		}
	}
	if _, _, ok := strings.Cut(b.Source, ":"); !ok {
		return fmt.Errorf("%s: source %q: want env:NAME, file:PATH or command:PROGRAM ARGS", b.Name, b.Source)
	}
	switch kind, rest, _ := strings.Cut(b.Source, ":"); kind {
	case "env":
		if !envRe.MatchString(rest) {
			return fmt.Errorf("%s: source %q", b.Name, b.Source)
		}
	case "file", "command":
		if strings.TrimSpace(rest) == "" {
			return fmt.Errorf("%s: source %q", b.Name, b.Source)
		}
	default:
		return fmt.Errorf("%s: source %q: want env:, file: or command:", b.Name, b.Source)
	}
	for _, e := range b.Env {
		if !envRe.MatchString(e) {
			return fmt.Errorf("%s: env %q", b.Name, e)
		}
	}
	return nil
}

// SplitHost splits "host" or "host:port"; the port defaults to 443,
// and a port that is not a number comes back empty.
func SplitHost(h string) (host, port string) {
	if hh, p, err := net.SplitHostPort(h); err == nil {
		if _, err := fmt.Sscanf(p, "%d", new(int)); err != nil {
			return hh, ""
		}
		return hh, p
	}
	return strings.Trim(h, "[]"), "443"
}

// Resolve reads the real value on the host: from the environment, a
// file, or a command's output (run without a shell, ten seconds at
// most). Surrounding whitespace is trimmed.
func Resolve(source, home string) (string, error) {
	kind, rest, _ := strings.Cut(source, ":")
	var v string
	switch kind {
	case "env":
		v = os.Getenv(rest)
		if v == "" {
			return "", fmt.Errorf("$%s is not set", rest)
		}
	case "file":
		p := strings.TrimSpace(rest)
		if p == "~" || strings.HasPrefix(p, "~/") {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		v = string(b)
	case "command":
		argv := strings.Fields(rest)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Stdin = nil
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("%s: %v", rest, err)
		}
		v = string(out)
	default:
		return "", errors.New("unknown source " + source)
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", errors.New("empty value")
	}
	if strings.ContainsAny(v, "\r\n") {
		return "", errors.New("the value spans lines; a credential is one token")
	}
	return v, nil
}

// Placeholder makes a stand-in of the value's shape: the same length,
// the same short prefix (ghp_, sk-), random letters and digits after
// it, so tools that check a token's form accept it.
func Placeholder(real string) string {
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	keep := 0
	if len(real) >= 20 {
		if i := strings.IndexAny(real, "_-"); i > 0 && i <= 4 {
			keep = i + 1
		}
	}
	for {
		b := []byte(real[:keep])
		for len(b) < max(len(real), 16) {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alnum))))
			b = append(b, alnum[n.Int64()])
		}
		if p := string(b); p != real {
			return p
		}
	}
}

// Live is a binding during a session: the value and its placeholder.
type Live struct {
	Name        string
	Hosts       []string
	Value       string
	Placeholder string
}

type Set []*Live

// For returns the credential bound to host:port, if any.
func (s Set) For(hostport string) *Live {
	host, port := SplitHost(hostport)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, l := range s {
		for _, h := range l.Hosts {
			bh, bp := SplitHost(h)
			bh = strings.ToLower(bh)
			if bp != port {
				continue
			}
			if bh == host || (strings.HasPrefix(bh, "*.") && strings.HasSuffix(host, bh[1:])) {
				return l
			}
		}
	}
	return nil
}

// Intercepts reports whether any credential is bound to host:port.
func (s Set) Intercepts(hostport string) bool { return s.For(hostport) != nil }

// Substitute puts the value in place of the placeholder in a request's
// headers and query, including inside Basic credentials. It reports
// whether the placeholder was there.
func (l *Live) Substitute(h http.Header, u *url.URL) bool {
	found := false
	for k, vs := range h {
		for i, v := range vs {
			if nv, ok := l.replaceHeader(v); ok {
				h[k][i] = nv
				found = true
			}
		}
	}
	if u != nil && strings.Contains(u.RawQuery, url.QueryEscape(l.Placeholder)) {
		u.RawQuery = strings.ReplaceAll(u.RawQuery, url.QueryEscape(l.Placeholder), url.QueryEscape(l.Value))
		found = true
	}
	return found
}

func (l *Live) replaceHeader(v string) (string, bool) {
	if strings.Contains(v, l.Placeholder) {
		return strings.ReplaceAll(v, l.Placeholder, l.Value), true
	}
	scheme, enc, ok := strings.Cut(v, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return v, false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil || !bytes.Contains(raw, []byte(l.Placeholder)) {
		return v, false
	}
	raw = bytes.ReplaceAll(raw, []byte(l.Placeholder), []byte(l.Value))
	return scheme + " " + base64.StdEncoding.EncodeToString(raw), true
}

// MaskHeader puts the placeholder back where a response header carries
// the value.
func (l *Live) MaskHeader(h http.Header) {
	for k, vs := range h {
		for i, v := range vs {
			if strings.Contains(v, l.Value) {
				h[k][i] = strings.ReplaceAll(v, l.Value, l.Placeholder)
			}
		}
	}
}

// MaskBody puts the placeholder back where a response body carries the
// value, so a host that echoes the request cannot hand it to the agent.
// The body must not be compressed.
func (l *Live) MaskBody(r io.ReadCloser) io.ReadCloser {
	return &masked{r: r, from: []byte(l.Value), to: []byte(l.Placeholder)}
}

type masked struct {
	r        io.ReadCloser
	from, to []byte
	buf, out []byte
	eof      bool
}

func (m *masked) Read(p []byte) (int, error) {
	for len(m.out) == 0 {
		if m.eof {
			if len(m.buf) == 0 {
				return 0, io.EOF
			}
			m.out, m.buf = bytes.ReplaceAll(m.buf, m.from, m.to), nil
			break
		}
		chunk := make([]byte, 32<<10)
		n, err := m.r.Read(chunk)
		m.buf = append(m.buf, chunk[:n]...)
		if err == io.EOF {
			m.eof = true
		} else if err != nil {
			return 0, err
		}
		m.buf = bytes.ReplaceAll(m.buf, m.from, m.to)
		if !m.eof {
			// Hold back only a tail that could be the start of a value
			// cut in two, so a stream (server-sent events) is not held up.
			keep := partial(m.buf, m.from)
			m.out = append(m.out, m.buf[:len(m.buf)-keep]...)
			m.buf = append([]byte(nil), m.buf[len(m.buf)-keep:]...)
		}
	}
	n := copy(p, m.out)
	m.out = m.out[n:]
	return n, nil
}

func (m *masked) Close() error { return m.r.Close() }

// partial returns the length of the longest tail of b that is a proper
// prefix of v.
func partial(b, v []byte) int {
	for k := min(len(v)-1, len(b)); k > 0; k-- {
		if bytes.Equal(b[len(b)-k:], v[:k]) {
			return k
		}
	}
	return 0
}

// SameLength reports whether masking keeps a body's length.
func (l *Live) SameLength() bool { return len(l.Value) == len(l.Placeholder) }
