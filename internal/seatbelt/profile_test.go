package seatbelt

import (
	"strings"
	"testing"
)

func TestProfile(t *testing.T) {
	p := Profile{
		Tag:     "airbag-s-1",
		Write:   []string{"/private/var/tmp/airbag-501/s-1/ws"},
		NoRead:  []string{"/Users/me/.ssh", "/Users/me/.aws"},
		NoWrite: []string{"/private/var/tmp/airbag-501/s-1/ws/.git/hooks"},
		Ports:   []int{51234},
		Sockets: []string{"/private/var/tmp/airbag-501/s-1/run/ctl.sock"},
	}
	s := p.String()
	for _, want := range []string{
		`(deny default (with message "airbag-s-1"))`,
		`(deny file-read* (subpath "/Users/me/.ssh"))`,
		`(allow file-write* (subpath "/private/var/tmp/airbag-501/s-1/ws"))`,
		`(deny file-write* (subpath "/private/var/tmp/airbag-501/s-1/ws/.git/hooks"))`,
		`(allow network-outbound (remote ip "localhost:51234"))`,
		`(allow network-outbound (remote unix-socket (path-literal "/private/var/tmp/airbag-501/s-1/run/ctl.sock")))`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("profile lacks %s", want)
		}
	}
	order := func(a, b string) {
		if strings.Index(s, a) > strings.Index(s, b) {
			t.Errorf("%q must come before %q: the last matching rule wins", a, b)
		}
	}
	order("(allow file-read*)", "(deny file-read*")
	order("(allow file-write* (subpath", "(deny file-write*")
	if strings.Contains(s, TrustdService) || strings.Contains(s, `remote ip "*`) {
		t.Error("trustd or open network by default")
	}
	if !strings.Contains((Profile{Trustd: true}).String(), TrustdService) {
		t.Error("Trustd not honoured")
	}
	if got := Quote(`a"b\c`); got != `"a\"b\\c"` {
		t.Errorf("Quote = %s", got)
	}
}
