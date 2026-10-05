package term

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

func TestSafe(t *testing.T) {
	for in, want := range map[string]string{ //nolint:gosec // terminal text, not credentials
		"plain\ttext\n":         "plain\ttext\n",
		"привет, мир":           "привет, мир",
		"a\x1b[2Jb":             `a\x1b[2Jb`,
		"title\x1b]0;pwned\x07": `title\x1b]0;pwned\x07`,
		"line\rover":            `line\rover`,
		"del\x7f c1\u009b":      `del\x7f c1\u009b`,
		"ok\u202eexe.txt":       "ok\\u202eexe.txt",
		"bad\xffbyte":           `bad\xffbyte`,
		"  is fine, é too\n":    "  is fine, é too\n",
	} {
		var b bytes.Buffer
		w := Safe(&b)
		_, _ = w.Write([]byte(in))
		w.Flush()
		if b.String() != want {
			t.Errorf("Safe(%q) = %q, want %q", in, b.String(), want)
		}
		if got := String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
}

// A UTF-8 sequence split across writes is joined, not escaped.
func TestSplitRune(t *testing.T) {
	var b bytes.Buffer
	w := Safe(&b)
	s := []byte("я\x1b")
	_, _ = w.Write(s[:1])
	_, _ = w.Write(s[1:])
	_, _ = w.Write([]byte{0xd0}) // never completed
	w.Flush()
	if b.String() != `я\x1b\xd0` {
		t.Fatalf("got %q", b.String())
	}
}

// Escaped text carries no byte or rune that can act on the terminal:
// no C0 control except tab and newline, no DEL, no C1, no bidi
// override. Escaping is idempotent, and the streaming Writer (fed at
// any boundaries) agrees with String.
func FuzzSafe(f *testing.F) {
	f.Add("plain text\n\tindented", 3)
	f.Add("\x1b]0;title\x07", 1)
	f.Add("a\u202eb", 2)
	f.Add("\xff\xfe", 7)
	f.Fuzz(func(t *testing.T, s string, chunk int) {
		got := String(s)
		for _, r := range got {
			if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) || bidi(r) {
				t.Fatalf("String(%q) left an active rune %U", s, r)
			}
		}
		// Invalid input bytes are shown as \xNN, so the output is always
		// valid UTF-8: no raw byte reaches the terminal.
		if !utf8.ValidString(got) {
			t.Fatalf("String(%q) is not valid UTF-8: %q", s, got)
		}
		if again := String(got); again != got {
			t.Fatalf("String is not idempotent: %q -> %q", got, again)
		}
		if chunk > 0 && chunk <= 4096 {
			var buf bytes.Buffer
			w := Safe(&buf)
			b := []byte(s)
			for len(b) > 0 {
				k := chunk
				if k > len(b) {
					k = len(b)
				}
				_, _ = w.Write(b[:k])
				b = b[k:]
			}
			w.Flush()
			if buf.String() != got {
				t.Fatalf("Writer (chunk %d) != String for %q:\n writer %q\n string %q", chunk, s, buf.String(), got)
			}
		}
	})
}

// Each edge of the escaped ranges: the control runes are escaped, their
// neighbours are not.
func TestSafeEdges(t *testing.T) {
	escaped := []rune{0x00, 0x1f, 0x7f, 0x80, 0x9f, 0x061c, 0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069}
	plain := []rune{0x20, 0x7e, 0xa0, 0x061b, 0x200d, 0x2029, 0x202f, 0x2065, 0x206a}
	for _, r := range escaped {
		if got := String(string(r)); got == string(r) {
			t.Errorf("%U was not escaped", r)
		}
	}
	for _, r := range plain {
		if got := String(string(r)); got != string(r) {
			t.Errorf("%U was escaped as %q", r, got)
		}
	}
	// A rune split across writes is held, not escaped byte by byte.
	var buf bytes.Buffer
	w := Safe(&buf)
	b := []byte("é\u202e")
	for i := range b {
		_, _ = w.Write(b[i : i+1])
	}
	w.Flush()
	if buf.String() != String("é\u202e") {
		t.Fatalf("split writes gave %q, want %q", buf.String(), String("é\u202e"))
	}
}
