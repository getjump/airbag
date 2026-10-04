package shim

import (
	"bytes"
	"testing"
)

func TestScriptArg(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		script string
		ok     bool
	}{
		{[]string{"-c", "ls"}, "ls", true},
		{[]string{"-lc", "ls -la"}, "ls -la", true},
		{[]string{"-e", "-o", "pipefail", "-c", "make"}, "make", true},
		{[]string{"--login", "-c", "x", "name", "arg"}, "x", true},
		{[]string{"script.sh"}, "", false},
		{nil, "", false},
	} {
		s, ok := scriptArg(tc.args)
		if s != tc.script || ok != tc.ok {
			t.Errorf("%v: got %q %v", tc.args, s, ok)
		}
	}
}

func TestMaskerAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	m := newMasker(&out, []secret{{"API_TOKEN", []byte("sk-test-1234567890")}})
	for _, chunk := range []string{"TOKEN=sk-te", "st-12345", "67890\nok\n"} {
		_, _ = m.Write([]byte(chunk))
	}
	m.Flush()
	if got := out.String(); got != "TOKEN=[airbag: masked API_TOKEN]\nok\n" {
		t.Fatalf("got %q", got)
	}
}
