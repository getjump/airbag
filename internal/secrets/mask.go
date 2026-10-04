package secrets

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/getjump/airbag/internal/creds"
)

// Masker replaces the registry's values with placeholders in a stream:
// each value as written, and as JSON encoders write it inside a string
// (jsonStyle). Nothing else is covered: a value encoded otherwise
// (base64, URL encoding), cut in pieces or changed passes as it is.
//
// A placeholder is made as for a credential (creds.Placeholder): the
// value's shape, never the value. It is made once, so every request of
// a session shows the model the same one.
type Masker struct {
	pats  []pattern
	first [256][]int // indexes into pats, by the first byte of from
	names []string   // in the registry's order
	ph    map[string]string
}

type pattern struct {
	from, to []byte
	name     string
}

// NewMasker masks the values of r. given holds placeholders that exist
// already, by value: a bound credential's, so the model sees the one
// the agent holds.
func NewMasker(r *Registry, given map[string]string) *Masker {
	m := &Masker{ph: map[string]string{}}
	vals := r.Values()
	seen := map[string]bool{}
	for _, v := range vals {
		ph := given[v.Value]
		if ph == "" || ph == v.Value {
			ph = newPlaceholder(v.Value, vals)
		}
		m.ph[v.Value] = ph
		if !slices.Contains(m.names, v.Name) {
			m.names = append(m.names, v.Name)
		}
		for _, st := range jsonStyles {
			from := st.escape(v.Value)
			if seen[from] {
				continue
			}
			seen[from] = true
			m.pats = append(m.pats, pattern{from: []byte(from), to: []byte(st.escape(ph)), name: v.Name})
		}
	}
	for k, p := range m.pats {
		m.first[p.from[0]] = append(m.first[p.from[0]], k)
	}
	return m
}

// newPlaceholder makes a placeholder for v that holds no registered
// value, so a replacement cannot put one back.
func newPlaceholder(v string, vals []Value) string {
	for try := 0; ; try++ {
		p := creds.Placeholder(v)
		if try == 100 || !slices.ContainsFunc(vals, func(w Value) bool { return strings.Contains(p, w.Value) }) {
			return p
		}
	}
}

func (m *Masker) placeholder(v string) string { return m.ph[v] }

// Count is how many replacements the values of one name had.
type Count struct {
	Name string
	N    int
}

// Reader masks what it reads from r.
func (m *Masker) Reader(r io.Reader) *Reader {
	return &Reader{m: m, r: r, counts: map[string]int{}}
}

// Reader is one masked stream. The result equals one pass over the
// whole input that, at each place, replaces the longest form that
// starts there; read boundaries change nothing. Only a tail that may
// be the start of a form is held back for the next read.
type Reader struct {
	m    *Masker
	r    io.Reader
	buf  []byte
	pend []byte // input not yet scanned to the end
	out  []byte
	eof  bool

	mu     sync.Mutex
	counts map[string]int
}

func (r *Reader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.eof {
			return 0, io.EOF // the last scan left nothing pending
		}
		if r.buf == nil {
			r.buf = make([]byte, 32<<10)
		}
		n, err := r.r.Read(r.buf)
		r.pend = append(r.pend, r.buf[:n]...)
		if err == io.EOF {
			r.eof = true
		} else if err != nil {
			return 0, err
		}
		r.scan()
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *Reader) scan() {
	b, pats := r.pend, r.m.pats
	start, i := 0, 0
	for i < len(b) {
		ks := r.m.first[b[i]]
		if len(ks) == 0 {
			i++
			continue
		}
		best, wait := -1, false
		for _, k := range ks {
			from := pats[k].from
			if len(b)-i >= len(from) {
				if (best < 0 || len(from) > len(pats[best].from)) && bytes.Equal(b[i:i+len(from)], from) {
					best = k
				}
			} else if !r.eof && bytes.HasPrefix(from, b[i:]) {
				// A longer form may start here; the next read decides.
				wait = true
			}
		}
		if wait {
			break
		}
		if best < 0 {
			i++
			continue
		}
		r.out = append(append(r.out, b[start:i]...), pats[best].to...)
		r.mu.Lock()
		r.counts[pats[best].name]++
		r.mu.Unlock()
		i += len(pats[best].from)
		start = i
	}
	r.out = append(r.out, b[start:i]...)
	r.pend = append(r.pend[:0], b[i:]...)
}

// Counts returns the replacements so far by name, in the registry's
// order; names without one are left out.
func (r *Reader) Counts() []Count {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Count
	for _, name := range r.m.names {
		if n := r.counts[name]; n > 0 {
			out = append(out, Count{name, n})
		}
	}
	return out
}

// jsonStyle is one way an encoder writes a string inside JSON: quotes
// and backslashes escaped, control characters as \n, \t, ... or \u00XX,
// and the options below. The masker tries every combination.
type jsonStyle struct {
	raw       bool // not escaped: the value as written
	uControls bool // every control character as \u00XX
	slash     bool // "/" as "\/" (PHP, some Java libraries)
	html      bool // <, >, &, U+2028 and U+2029 as \u escapes (Go's encoding/json)
	ascii     bool // all but printable ASCII as \u escapes (Python's json.dumps)
	upper     bool // upper case hex digits
}

var jsonStyles = func() []jsonStyle {
	out := []jsonStyle{{raw: true}}
	for i := 0; i < 32; i++ {
		out = append(out, jsonStyle{uControls: i&1 != 0, slash: i&2 != 0, html: i&4 != 0, ascii: i&8 != 0, upper: i&16 != 0})
	}
	return out
}()

var shortEscape = [0x20]byte{'\b': 'b', '\t': 't', '\n': 'n', '\f': 'f', '\r': 'r'}

func (st jsonStyle) escape(s string) string {
	if st.raw {
		return s
	}
	hex := "0123456789abcdef"
	if st.upper {
		hex = "0123456789ABCDEF"
	}
	var b strings.Builder
	u := func(r rune) {
		b.WriteString(`\u`)
		for shift := 12; shift >= 0; shift -= 4 {
			b.WriteByte(hex[r>>shift&0xf])
		}
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteByte(s[i]) // not UTF-8: no encoder writes it otherwise
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteByte(byte(r))
		case r < 0x20 && shortEscape[r] != 0 && !st.uControls:
			b.WriteByte('\\')
			b.WriteByte(shortEscape[r])
		case r < 0x20:
			u(r)
		case r == '/' && st.slash:
			b.WriteString(`\/`)
		case st.html && (r == '<' || r == '>' || r == '&' || r == ' ' || r == ' '):
			u(r)
		case st.ascii && r > 0xffff:
			r -= 0x10000
			u(0xd800 + r>>10)
			u(0xdc00 + r&0x3ff)
		case st.ascii && r >= 0x7f:
			u(r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// jsonForms are the distinct forms of v the masker replaces, v itself
// first.
func jsonForms(v string) []string {
	var out []string
	for _, st := range jsonStyles {
		if f := st.escape(v); !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}
