// Package secrets is the registry of a session's secret values: the
// values of what airbag already treats as secret, each with a name that
// says where it came from. The values stay in the airbag process on the
// host; only the names are logged, stored or shown.
//
// What is registered:
//
//   - each value in the workspace's .env files (the ones secretfs
//     serves), named FILE#KEY, if it passes Worth;
//   - the other secret files (keys, cloud credentials, .npmrc, ...) as a
//     whole, named FILE, and the pieces of their lines that pass Worth
//     (the body lines of a PEM key, a token after "="), named FILE:LINE;
//   - credentials bound to hosts and the user's `secrets:` entries,
//     named "credential NAME" and "secret NAME", whatever Worth says.
//
// Worth is meant to give very few false positives: an ordinary value
// that is registered would be masked wherever it appears.
package secrets

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/getjump/airbag/internal/secretfs"
)

// MinLen is the shortest value Worth takes; MinMarked the shortest
// value the user marks or binds that is registered at all, so a short
// word cannot mask every occurrence of it.
const (
	MinLen    = 12
	MinMarked = 6
)

// Value is one registered value and where it came from.
type Value struct {
	Name  string
	Value string
}

// Worth is the rule for a value found in a secret file: at least 12
// characters, no white space, not a file path, letters and digits both,
// and at least four changes between lower case, upper case and digits
// from one letter or digit to the next. Random tokens pass; words,
// numbers, host names, versions and URLs without a password do not:
// "true", "3000", "production", "localhost:5432", "us-east-1",
// "my-bucket-2024", "http://localhost:3000".
func Worth(v string) bool {
	if len(v) < MinLen {
		return false
	}
	for _, p := range []string{"/", "./", "../", "~/"} {
		if strings.HasPrefix(v, p) {
			return false
		}
	}
	return varied(v, false)
}

// varied: letters and digits, and four changes of class between
// neighbouring letters and digits; other characters are passed over.
func varied(v string, spaces bool) bool {
	letter, digit := false, false
	changes, prev := 0, 0
	for i := 0; i < len(v); i++ {
		c, class := v[i], 0
		switch {
		case 'a' <= c && c <= 'z':
			class, letter = 1, true
		case 'A' <= c && c <= 'Z':
			class, letter = 2, true
		case '0' <= c && c <= '9':
			class, digit = 3, true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if !spaces {
				return false
			}
		case c < 0x20 || c == 0x7f:
			return false
		}
		if class != 0 {
			if prev != 0 && class != prev {
				changes++
			}
			prev = class
		}
	}
	return letter && digit && changes >= 4
}

// Entry is one KEY=value of a .env file. Start and End are the byte
// offsets of the value as written, inside its quotes if it has any.
type Entry struct {
	Key, Value string
	Start, End int
}

var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// ParseDotenv reads KEY=value lines as dotenv libraries do: `export `
// before the key, comments, single, double and backtick quotes (which
// may span lines), escapes in double quotes, and " #" ending an
// unquoted value.
func ParseDotenv(b []byte) []Entry {
	s := string(b)
	var out []Entry
	for i := 0; i < len(s); {
		eol := strings.IndexByte(s[i:], '\n')
		if eol < 0 {
			eol = len(s)
		} else {
			eol += i
		}
		next := eol + 1
		j := i + len(s[i:eol]) - len(strings.TrimLeft(s[i:eol], " \t"))
		if rest, ok := strings.CutPrefix(s[j:eol], "export "); ok {
			j = eol - len(strings.TrimLeft(rest, " \t"))
		}
		eq := strings.IndexByte(s[j:eol], '=')
		if eq < 0 || strings.HasPrefix(s[j:eol], "#") {
			i = next
			continue
		}
		key := strings.TrimSpace(s[j : j+eq])
		v := j + eq + 1
		for v < eol && (s[v] == ' ' || s[v] == '\t') {
			v++
		}
		e := Entry{Key: key}
		if v < eol && (s[v] == '"' || s[v] == '\'' || s[v] == '`') {
			q, k := s[v], v+1
			for k < len(s) && s[k] != q {
				if q == '"' && s[k] == '\\' {
					k++
				}
				k++
			}
			if k >= len(s) { // no closing quote: the rest of the line
				e.Start, e.End = v+1, len(strings.TrimRight(s[:eol], "\r"))
				if e.End < e.Start {
					e.End = e.Start
				}
			} else {
				e.Start, e.End = v+1, k
				if n := strings.IndexByte(s[k:], '\n'); n >= 0 {
					next = k + n + 1
				} else {
					next = len(s)
				}
			}
			e.Value = s[e.Start:e.End]
			if q == '"' {
				e.Value = unescape(e.Value)
			}
		} else {
			end := eol
			for _, c := range []string{" #", "\t#"} {
				if h := strings.Index(s[v:end], c); h >= 0 {
					end = v + h
				}
			}
			for end > v && strings.ContainsRune(" \t\r", rune(s[end-1])) {
				end--
			}
			e.Start, e.End, e.Value = v, end, s[v:end]
		}
		if keyRe.MatchString(key) {
			out = append(out, e)
		}
		i = next
	}
	return out
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '"', '\\', '$', '`':
			b.WriteByte(s[i])
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// IsDotenv reports whether a secret file's base name is a .env file,
// read as KEY=value lines.
func IsDotenv(base string) bool {
	return secretfs.IsSecret(base) && (base == ".env" || strings.HasPrefix(base, ".env."))
}

// pieces are the parts of a line that may be a value on their own: each
// field between spaces, without quotes and a trailing comma; the part
// after "=" of a field too (".npmrc": //host/:_authToken=VALUE); and
// for a URL with a password, the password instead of the URL.
func pieces(line string) []string {
	var out []string
	for _, f := range strings.Fields(line) {
		f = strings.TrimRight(strings.Trim(f, `"'`), ",;")
		f = strings.Trim(f, `"'`)
		if f == "" {
			continue
		}
		if i := strings.Index(f, "://"); i >= 0 {
			if pw := password(f[i+3:]); pw != "" {
				out = append(out, pw)
				continue
			}
		}
		out = append(out, f)
		if _, rhs, ok := strings.Cut(f, "="); ok {
			out = append(out, strings.Trim(rhs, `"'`))
		}
	}
	return out
}

// password is the password in the authority of a URL (after "://"),
// as written.
func password(rest string) string {
	auth, _, _ := strings.Cut(rest, "/")
	at := strings.LastIndex(auth, "@")
	if at < 0 {
		return ""
	}
	_, pw, _ := strings.Cut(auth[:at], ":")
	return pw
}

// found registers what Worth takes of one value: the pieces of each of
// its lines, and a value that spans lines as a whole when it is varied.
func found(name, v string) []Value {
	var out []Value
	if strings.ContainsAny(v, "\n") {
		if w := strings.TrimSpace(v); len(w) >= MinLen && varied(w, true) {
			out = append(out, Value{name, w})
		}
	}
	for _, line := range strings.Split(v, "\n") {
		for _, p := range pieces(line) {
			if Worth(p) {
				out = append(out, Value{name, p})
			}
		}
	}
	return out
}

// FromFile reads the values of one secret file, rel being its path in
// the workspace.
func FromFile(rel string, b []byte) []Value {
	rel = filepath.ToSlash(rel)
	var out []Value
	if IsDotenv(path.Base(rel)) {
		for _, e := range ParseDotenv(b) {
			out = append(out, found(rel+"#"+e.Key, e.Value)...)
		}
		return out
	}
	if w := string(bytes.TrimSpace(b)); len(w) >= MinLen && varied(w, true) {
		out = append(out, Value{rel, w})
	}
	for n, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-----") {
			continue
		}
		for _, p := range pieces(line) {
			if Worth(p) {
				out = append(out, Value{fmt.Sprintf("%s:%d", rel, n+1), p})
			}
		}
	}
	return out
}

// maxFile: larger files are not secret files worth reading whole.
const maxFile = 1 << 20

// FromFiles reads the workspace's secret files, the ones secretfs
// serves, as they are on the host.
func FromFiles(ws string) []Value {
	var out []Value
	for _, rel := range secretfs.Find(ws) {
		p := filepath.Join(ws, rel)
		if st, err := os.Stat(p); err != nil || st.Size() > maxFile {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		out = append(out, FromFile(rel, b)...)
	}
	return out
}

// Marked registers a value the user bound or marked: as a whole,
// whatever Worth says, once it is MinMarked long; a value that spans
// lines also by the pieces of its lines.
func Marked(name, v string) []Value {
	v = strings.TrimSpace(v)
	if len(v) < MinMarked {
		return nil
	}
	out := []Value{{name, v}}
	if strings.Contains(v, "\n") {
		out = append(out, found(name, v)...)
	}
	return out
}

// Registry is the session's set of secret values, each value once,
// under the first name it was found by.
type Registry struct {
	vals []Value
	seen map[string]bool
}

func New(vs ...Value) *Registry {
	r := &Registry{seen: map[string]bool{}}
	r.Add(vs...)
	return r
}

func (r *Registry) Add(vs ...Value) {
	for _, v := range vs {
		if v.Value == "" || r.seen[v.Value] {
			continue
		}
		r.seen[v.Value] = true
		r.vals = append(r.vals, v)
	}
}

// Len is the number of values.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.vals)
}

// Values returns the registered values in the order they were added.
func (r *Registry) Values() []Value {
	if r == nil {
		return nil
	}
	return append([]Value(nil), r.vals...)
}

// Names returns the distinct names, in order.
func (r *Registry) Names() []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range r.Values() {
		if !seen[v.Name] {
			seen[v.Name] = true
			out = append(out, v.Name)
		}
	}
	return out
}

// Found returns the names of the values b holds, in order.
func (r *Registry) Found(b []byte) []string {
	var out []string
	for _, v := range r.Values() {
		if bytes.Contains(b, []byte(v.Value)) && !contains(out, v.Name) {
			out = append(out, v.Name)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
