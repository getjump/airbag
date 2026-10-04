// Package term keeps text the agent controls from acting on the user's
// terminal. File names, command lines, hosts, commit messages and file
// contents in review, diff and logs come from the sandbox; printed as
// is, escape sequences in them could move the cursor, rewrite earlier
// lines or retitle the window, and hide what the review is there to
// show.
package term

import (
	"fmt"
	"io"
	"unicode/utf8"
)

// Writer shows control characters as visible escapes: C0 except tab and
// newline, DEL, C1, and the Unicode bidirectional controls that reorder
// text on screen ("Trojan Source"). Bytes that are not UTF-8 show as
// \xNN. Call Flush at the end of output.
type Writer struct {
	w    io.Writer
	rest []byte // an incomplete UTF-8 sequence held for the next write
}

func Safe(w io.Writer) *Writer { return &Writer{w: w} }

func (s *Writer) Write(p []byte) (int, error) {
	b := append(s.rest, p...)
	s.rest = nil
	var out []byte
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size <= 1 {
			if !utf8.FullRune(b) {
				s.rest = append([]byte(nil), b...)
				break
			}
			out = fmt.Appendf(out, `\x%02x`, b[0])
			b = b[1:]
			continue
		}
		out = appendRune(out, r, b[:size])
		b = b[size:]
	}
	if _, err := s.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush writes out a trailing incomplete sequence as escapes.
func (s *Writer) Flush() {
	var out []byte
	for _, c := range s.rest {
		out = fmt.Appendf(out, `\x%02x`, c)
	}
	s.rest = nil
	if len(out) > 0 {
		_, _ = s.w.Write(out)
	}
}

// String returns s with the same escapes, for text built in memory.
func String(s string) string {
	var out []byte
	b := []byte(s)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size <= 1 {
			out = fmt.Appendf(out, `\x%02x`, b[0])
			b = b[1:]
			continue
		}
		out = appendRune(out, r, b[:size])
		b = b[size:]
	}
	return string(out)
}

func appendRune(out []byte, r rune, raw []byte) []byte {
	switch {
	case r == '\n' || r == '\t':
		return append(out, raw...)
	case r == '\r':
		return append(out, `\r`...)
	case r < 0x20 || r == 0x7f:
		return fmt.Appendf(out, `\x%02x`, r)
	case r >= 0x80 && r <= 0x9f, bidi(r):
		return fmt.Appendf(out, `\u%04x`, r)
	}
	return append(out, raw...)
}

func bidi(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}
