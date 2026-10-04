package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"
	"testing/iotest"
)

// The values of the masking tests: a plain token, and values with each
// kind of character a JSON encoder escapes.
var maskVals = []Value{
	{"token", "sk-live-4fG7xQ2mZ9abcDEF"},
	{"quoted", "ab\"cD\\eF12gH34\tiJ"},
	{"lines", "-----BEGIN KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEF\n-----END KEY-----"},
	{"html", "a<b>&c/D9e8F7g6"},
	{"unicode", "pässwörd-Xy12Zq9€"},
	{"control", "x\x01y\x1fZ9q8W7e6"},
}

func maskAll(m *Masker, b []byte) ([]byte, []Count) {
	r := m.Reader(bytes.NewReader(b))
	out, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}
	return out, r.Counts()
}

// A value goes out as its placeholder whether the body carries it as
// written or JSON-escaped, as Node and Rust (minimal escapes), Go
// (<, >, & as \u escapes) and Python (non-ASCII as \u escapes) write
// it; inside JSON the placeholder decodes to itself.
func TestMaskVerbatimAndJSON(t *testing.T) {
	m := NewMasker(New(maskVals...), nil)
	for _, v := range maskVals {
		ph := m.placeholder(v.Value)
		bodies := map[string]string{
			"verbatim": "x " + v.Value + " y",
			"go":       goJSON(v.Value, true),
			"node":     goJSON(v.Value, false),
			"python":   pyJSON(v.Value),
		}
		for enc, body := range bodies {
			out, counts := maskAll(m, []byte(body))
			for _, f := range jsonForms(v.Value) {
				if bytes.Contains(out, []byte(f)) {
					t.Errorf("%s, %s: a form of the value is left: %q", v.Name, enc, out)
				}
			}
			if len(counts) != 1 || counts[0] != (Count{v.Name, 1}) {
				t.Errorf("%s, %s: counts %v", v.Name, enc, counts)
			}
			if enc == "verbatim" {
				if want := "x " + ph + " y"; string(out) != want {
					t.Errorf("%s: %q, want %q", v.Name, out, want)
				}
				continue
			}
			var got struct{ S string }
			if err := json.Unmarshal(out, &got); err != nil || got.S != ph {
				t.Errorf("%s, %s: %q does not decode to the placeholder %q (%v)", v.Name, enc, out, ph, err)
			}
		}
	}
}

func goJSON(v string, html bool) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(html)
	_ = e.Encode(map[string]string{"S": v})
	return strings.TrimSpace(b.String())
}

// pyJSON writes as Python's json.dumps does by default (ensure_ascii).
func pyJSON(v string) string {
	var b strings.Builder
	b.WriteString(`{"S": "`)
	for _, r := range v {
		switch {
		case r == '"' || r == '\\':
			b.WriteString(`\` + string(r))
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		case r > 0xffff:
			r -= 0x10000
			fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	b.WriteString(`"}`)
	return b.String()
}

// The placeholder has the value's shape and is never the value; a
// bound credential keeps the placeholder the agent already holds.
func TestMaskPlaceholders(t *testing.T) {
	cred := Value{"credential gh", "ghp_e2eRealToken0123456789abcdefABCDEF"}
	m := NewMasker(New(append(maskVals, cred)...), map[string]string{cred.Value: "ghp_given0placeholder00000000000000000"})
	for _, v := range maskVals {
		ph := m.placeholder(v.Value)
		if ph == v.Value || len(ph) != max(len(v.Value), 16) || strings.Contains(ph, v.Value) {
			t.Errorf("%s: placeholder %q", v.Name, ph)
		}
	}
	if ph := m.placeholder(cred.Value); ph != "ghp_given0placeholder00000000000000000" {
		t.Errorf("credential placeholder %q", ph)
	}
}

// A value cut by the reads, at any boundary, is masked as in one piece,
// and nothing is held back that cannot be the start of a value.
func TestMaskSplitAcrossReads(t *testing.T) {
	m := NewMasker(New(maskVals...), nil)
	var body []byte
	for i, v := range maskVals {
		body = append(body, fmt.Sprintf("part %d: %s; %s\n", i, v.Value, goJSON(v.Value, i%2 == 0))...)
	}
	want, wantCounts := maskAll(m, body)
	for _, n := range []int{1, 2, 3, 5, 7, 13, 64, 4096} {
		r := m.Reader(&chunked{data: body, n: n})
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("reads of %d: %q\nwant %q", n, got, want)
		}
		if c := r.Counts(); fmt.Sprint(c) != fmt.Sprint(wantCounts) {
			t.Fatalf("reads of %d: counts %v, want %v", n, c, wantCounts)
		}
	}
	got, _ := io.ReadAll(m.Reader(iotest.OneByteReader(bytes.NewReader(body))))
	if !bytes.Equal(got, want) {
		t.Fatalf("one byte at a time: %q", got)
	}
	for _, v := range maskVals {
		if bytes.Contains(want, []byte(v.Value)) {
			t.Fatalf("%s left in %q", v.Name, want)
		}
	}
}

// A body that cannot hold the start of a value flows on at once: a
// read is not held up for more input.
func TestMaskDoesNotHoldUp(t *testing.T) {
	m := NewMasker(New(maskVals...), nil)
	pr, pw := io.Pipe()
	r := m.Reader(pr)
	go func() { _, _ = pw.Write([]byte(`{"messages":[`)) }()
	buf := make([]byte, 64)
	n, err := r.Read(buf)
	if err != nil || string(buf[:n]) != `{"messages":[` {
		t.Fatalf("held back: %q %v", buf[:n], err)
	}
	pw.Close()
}

// Where values overlap, the one that starts first wins, and of those
// that start at one place the longest: a whole key is one replacement,
// not its lines one by one.
func TestMaskLongestFirst(t *testing.T) {
	whole := maskVals[2]
	line := Value{"lines:2", "MIIBVgIBADANBgkqhkiG9w0BAQEF"}
	m := NewMasker(New(whole, line), nil)
	out, counts := maskAll(m, []byte(whole.Value+" and "+line.Value))
	if want := m.placeholder(whole.Value) + " and " + m.placeholder(line.Value); string(out) != want {
		t.Fatalf("%q, want %q", out, want)
	}
	if fmt.Sprint(counts) != fmt.Sprint([]Count{{"lines", 1}, {"lines:2", 1}}) {
		t.Fatalf("counts %v", counts)
	}
}

// Counts are by name, in the registry's order; names without a
// replacement are left out.
func TestMaskCounts(t *testing.T) {
	m := NewMasker(New(maskVals...), nil)
	_, counts := maskAll(m, []byte(maskVals[3].Value+maskVals[0].Value+goJSON(maskVals[0].Value, true)))
	if want := []Count{{"token", 2}, {"html", 1}}; fmt.Sprint(counts) != fmt.Sprint(want) {
		t.Fatalf("counts %v, want %v", counts, want)
	}
	if _, c := maskAll(NewMasker(New(), nil), []byte("nothing")); len(c) != 0 {
		t.Fatalf("empty registry: %v", c)
	}
}

// Masking a stream, read at any boundaries, equals masking it whole by
// the plain rule: at each place the longest pattern that matches there.
func FuzzMask(f *testing.F) {
	f.Add("abcdef", "abcdefgh", "xxabcdefghabcdefxx", 3, int64(1))
	f.Add("aaaaaa", "aaaaab", "aaaaaaaaaab", 1, int64(2))
	f.Add("ab\"cdef", "a\nbcdef", `ab\"cdef a\nbcdef`, 2, int64(3))
	f.Fuzz(func(t *testing.T, v1, v2, body string, chunk int, seed int64) {
		if len(v1) < MinMarked || len(v2) < MinMarked || len(v1) > 256 || len(v2) > 256 || len(body) > 8192 || chunk <= 0 || chunk > 4096 {
			return
		}
		m := NewMasker(New(Value{"one", v1}, Value{"two", v2}), nil)
		want := reference(m, []byte(body))
		rnd := rand.New(rand.NewSource(seed))
		got, err := io.ReadAll(m.Reader(&chunked{data: []byte(body), n: chunk, rnd: rnd}))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("v1=%q v2=%q body=%q chunk=%d\n got %q\nwant %q", v1, v2, body, chunk, got, want)
		}
	})
}

// reference masks b whole, the slow and obvious way.
func reference(m *Masker, b []byte) []byte {
	var out []byte
	for i := 0; i < len(b); {
		best := -1
		for k, p := range m.pats {
			if bytes.HasPrefix(b[i:], p.from) && (best < 0 || len(p.from) > len(m.pats[best].from)) {
				best = k
			}
		}
		if best < 0 {
			out = append(out, b[i])
			i++
			continue
		}
		out = append(out, m.pats[best].to...)
		i += len(m.pats[best].from)
	}
	return out
}

// chunked hands out its data n bytes at a time, or a random 1..n with rnd.
type chunked struct {
	data []byte
	n    int
	rnd  *rand.Rand
}

func (c *chunked) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := c.n
	if c.rnd != nil {
		n = 1 + c.rnd.Intn(c.n)
	}
	n = copy(p, c.data[:min(n, len(c.data))])
	c.data = c.data[n:]
	return n, nil
}
