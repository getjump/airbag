package creds

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
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
	f.Add("tok_secret", "tok_FAKE00", "head tok_secret tail", 3, 1)
	f.Add("aa", "PP", "aaaa", 1, 3)
	f.Add("ab", "xaby", "abab", 2, 1) // the placeholder holds the value
	f.Fuzz(func(t *testing.T, value, placeholder, body string, chunk, buf int) {
		if value == "" || chunk <= 0 || chunk > 4096 || buf <= 0 || buf > 4096 {
			return
		}
		l := &Live{Value: value, Placeholder: placeholder}
		r := l.MaskBody(io.NopCloser(&slow{data: []byte(body), n: chunk}))
		// Read with the agent's buffer size, and make sure every read
		// that is not the end gives something: the stream must flow.
		var out []byte
		p := make([]byte, buf)
		for empty := 0; ; {
			n, err := r.Read(p)
			out = append(out, p[:n]...)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if n == 0 {
				if empty++; empty > len(body)+2 {
					t.Fatalf("value=%q body=%q chunk=%d buf=%d: the stream stalled", value, body, chunk, buf)
				}
			}
		}
		// The sound invariant: the stream, read at any boundaries,
		// equals one left-to-right replace of the value. (A value can
		// still reappear when the placeholder tiles into it, which a
		// same-length random placeholder does not do in practice, so
		// equality to ReplaceAll is the right property, not absence.)
		want := bytes.ReplaceAll([]byte(body), []byte(value), []byte(placeholder))
		if !bytes.Equal(out, want) {
			t.Fatalf("value=%q ph=%q body=%q chunk=%d buf=%d\n got %q\nwant %q", value, placeholder, body, chunk, buf, out, want)
		}
		// With a placeholder of the value's length (as in production)
		// each byte out stands for one byte in, so what is held back
		// after a read is known: it must be the start of a match, no
		// more. Holding more would stall a client that waits for the
		// rest of a response before it sends more.
		if len(placeholder) != len(value) {
			return
		}
		src := &slow{data: []byte(body), n: chunk}
		r = l.MaskBody(io.NopCloser(src))
		big := make([]byte, len(body)+1)
		emitted := 0
		for {
			n, err := r.Read(big)
			emitted += n
			if err != nil {
				break
			}
			in := len(body) - len(src.data)
			held := body[emitted:in]
			if len(held) >= len(value) || !strings.HasPrefix(value, held) {
				t.Fatalf("value=%q body=%q chunk=%d: after %d bytes in, held back %q", value, body, chunk, in, held)
			}
		}
	})
}

// The prefix rule at its edges: a separator at index 1..4 of a value of
// 20 or more is kept; a shorter value or a later separator is not.
func TestPlaceholderPrefixEdges(t *testing.T) {
	pad := func(prefix string, n int) string { return prefix + strings.Repeat("x", n-len(prefix)) }
	for _, c := range []struct {
		v    string
		keep string
	}{
		{pad("ghp_", 20), "ghp_"},   // length 20: kept
		{pad("ghp_", 19), ""},       // length 19: not
		{pad("abcd_", 20), "abcd_"}, // separator at index 4: kept
		{pad("abcde_", 20), ""},     // index 5: not
		{pad("_", 20), ""},          // index 0: not
		{pad("a-", 20), "a-"},       // index 1, dash: kept
	} {
		p := Placeholder(c.v)
		if c.keep != "" && !strings.HasPrefix(p, c.keep) {
			t.Errorf("Placeholder(%q) = %q, want prefix %q", c.v, p, c.keep)
		}
		// The random part is alphanumeric: a separator means a prefix
		// was kept.
		if c.keep == "" && strings.ContainsAny(p, "_-") {
			t.Errorf("Placeholder(%q) = %q kept a prefix it should not", c.v, p)
		}
	}
}

// An empty value cannot be in a body; masking passes it through.
func TestMaskBodyEmptyValue(t *testing.T) {
	l := &Live{Value: "", Placeholder: "x"}
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(l.MaskBody(io.NopCloser(strings.NewReader("body"))))
		done <- b
	}()
	select {
	case b := <-done:
		if string(b) != "body" {
			t.Fatalf("got %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a body masked for an empty value never returned")
	}
}

// A credential on *.example.com goes only to a name ending in
// .example.com, written without brackets: a bracket holds an IP
// literal, which no such name is.
func FuzzForHost(f *testing.F) {
	for _, h := range []string{"a.example.com", "a.example.com:443", "A.Example.com.:0443", "a.example.com[", "[a.example.com]", "[a.example.com]:443", "a.example.com]", "example.com", "[::1]:443", "].eXAmple.Com"} {
		f.Add(h)
	}
	s := Set{&Live{Name: "g", Hosts: []string{"*.example.com"}, Value: "realvalue-1234567890", Placeholder: "fakevalue-0987654321"}}
	f.Fuzz(func(t *testing.T, h string) {
		if s.For(h) == nil {
			return
		}
		name := h
		if i := strings.LastIndexByte(h, ':'); i >= 0 {
			name = h[:i]
		}
		if strings.ContainsAny(h, "[]") || !strings.HasSuffix(strings.ToLower(strings.TrimSuffix(name, ".")), ".example.com") {
			t.Fatalf("For(%q) gave the *.example.com credential", h)
		}
	})
}
