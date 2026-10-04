package creds

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// A placeholder stands in for a token: never equal to it, the same
// length (or 16 if the token is shorter), and the same short prefix so
// a tool that checks the token's shape still accepts it.
func FuzzPlaceholder(f *testing.F) {
	f.Add("ghp_abcdefghijklmnopqrstuvwxyz0123456789")
	f.Add("short")
	f.Add("sk-ABCDEFGHIJKLMNOPQRST")
	f.Fuzz(func(t *testing.T, v string) {
		if v == "" {
			return
		}
		p := Placeholder(v)
		if p == v {
			t.Fatalf("placeholder equals the value %q", v)
		}
		want := len(v)
		if want < 16 {
			want = 16
		}
		if len(p) != want {
			t.Fatalf("len(placeholder)=%d, want %d for %q", len(p), want, v)
		}
		if len(v) >= 20 {
			if i := strings.IndexAny(v, "_-"); i > 0 && i <= 4 {
				if p[:i+1] != v[:i+1] {
					t.Fatalf("placeholder %q dropped the prefix of %q", p, v)
				}
			}
		}
	})
}

// Masking a response stream, whatever the read boundaries, must equal a
// single replace of the value by the placeholder: the agent never sees
// the real value, and nothing else is altered.
func FuzzMaskBody(f *testing.F) {
	f.Add("tok_secret", "tok_FAKE00", "head tok_secret tail", 3)
	f.Add("aa", "PP", "aaaa", 1)
	f.Fuzz(func(t *testing.T, value, placeholder, body string, chunk int) {
		if value == "" || chunk <= 0 || chunk > 4096 {
			return
		}
		// Only assert where the reference is unambiguous.
		if bytes.Contains([]byte(placeholder), []byte(value)) {
			return
		}
		l := &Live{Value: value, Placeholder: placeholder}
		r := l.MaskBody(io.NopCloser(&chunked{data: []byte(body), n: chunk}))
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		// The sound invariant: the stream, read at any boundaries,
		// equals one left-to-right replace of the value. (A value can
		// still reappear when the placeholder tiles into it, which a
		// same-length random placeholder does not do in practice, so
		// equality to ReplaceAll is the right property, not absence.)
		want := bytes.ReplaceAll([]byte(body), []byte(value), []byte(placeholder))
		if !bytes.Equal(out, want) {
			t.Fatalf("value=%q ph=%q body=%q chunk=%d\n got %q\nwant %q", value, placeholder, body, chunk, out, want)
		}
	})
}

type chunked struct {
	data []byte
	n    int
}

func (c *chunked) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	k := c.n
	if k > len(c.data) {
		k = len(c.data)
	}
	n := copy(p, c.data[:k])
	c.data = c.data[n:]
	return n, nil
}
