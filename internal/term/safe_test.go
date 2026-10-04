package term

import (
	"bytes"
	"testing"
)

func TestSafe(t *testing.T) {
	for in, want := range map[string]string{
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
