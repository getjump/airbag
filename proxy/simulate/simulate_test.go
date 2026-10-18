package simulate

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func mustCompile(t *testing.T, stubs ...Stub) *Set {
	t.Helper()
	s, err := Compile(stubs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func req(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestMatchFirstWins(t *testing.T) {
	s := mustCompile(t,
		Stub{Name: "charge", Match: Match{Method: "post", Host: "API.Pay.test.", Path: "/v1/charges"}, Respond: Respond{Status: 201, Body: "created"}},
		Stub{Name: "one", Match: Match{Host: "api.pay.test", Path: "/v1/charges/*"}, Respond: Respond{Body: "one"}},
		Stub{Name: "deep", Match: Match{Host: "api.pay.test", Path: "/v1/**"}, Respond: Respond{Status: 503}},
		Stub{Name: "usd", Match: Match{Host: "*.pay.test", Query: map[string]string{"currency": "usd"}, Headers: map[string]string{"x-test": "y*"}}, Respond: Respond{Body: "usd"}},
	)
	cases := []struct {
		host, port, method, url string
		h                       http.Header
		want                    string // stub name, "" for none
	}{
		{"api.pay.test", "443", "POST", "/v1/charges", nil, "charge"},
		{"api.pay.test", "80", "POST", "/v1/charges", nil, "charge"},
		// Methods are case-sensitive on the wire; the config's is upper-cased.
		{"api.pay.test", "443", "post", "/v1/charges", nil, "deep"},
		{"api.pay.test", "443", "GET", "/v1/charges", nil, "deep"},
		{"api.pay.test", "443", "GET", "/v1/charges/ch_1", nil, "one"},
		// * stays within a segment; ** does not.
		{"api.pay.test", "443", "GET", "/v1/charges/ch_1/refunds", nil, "deep"},
		{"api.pay.test", "443", "GET", "/v2/x", nil, ""},
		{"api.pay.test", "443", "GET", "/", nil, ""},
		{"API.PAY.TEST.", "443", "POST", "/v1/charges", nil, "charge"},
		// A port the stub does not name is not simulated.
		{"api.pay.test", "8443", "POST", "/v1/charges", nil, ""},
		{"eu.pay.test", "443", "GET", "/x?currency=usd", http.Header{"X-Test": {"yes"}}, "usd"},
		{"eu.pay.test", "443", "GET", "/x?currency=eur", http.Header{"X-Test": {"yes"}}, ""},
		{"eu.pay.test", "443", "GET", "/x?currency=usd", http.Header{"X-Test": {"no"}}, ""},
		{"eu.pay.test", "443", "GET", "/x?currency=usd&currency=eur", http.Header{"X-Test": {"no", "yes"}}, "usd"},
		// A query that does not parse matches no stub that asks about it.
		{"eu.pay.test", "443", "GET", "/x?currency=usd&%zz", http.Header{"X-Test": {"yes"}}, ""},
		{"pay.test", "443", "GET", "/x?currency=usd", http.Header{"X-Test": {"yes"}}, ""},
		{"notpay.test", "443", "GET", "/x?currency=usd", http.Header{"X-Test": {"yes"}}, ""},
	}
	for _, c := range cases {
		r := s.Match(c.host, c.port, c.method, req(t, c.url), c.h)
		got := ""
		if r != nil {
			got = r.Stub
		}
		if got != c.want {
			t.Errorf("%s %s:%s%s: stub %q, want %q", c.method, c.host, c.port, c.url, got, c.want)
		}
	}
	if !s.Covers("api.pay.test", "443") || !s.Covers("x.pay.test", "80") || s.Covers("api.pay.test", "8443") || s.Covers("pay.test", "443") || s.Covers("other.test", "443") {
		t.Fatal("Covers disagrees with the stubs' hosts")
	}
	if got := strings.Join(s.Hosts(), ","); got != "api.pay.test,*.pay.test" {
		t.Fatalf("Hosts %q", got)
	}
}

func TestPortNamedCoversOnlyThatPort(t *testing.T) {
	s := mustCompile(t, Stub{Match: Match{Host: "svc.corp.test:08443"}})
	if !s.Covers("svc.corp.test", "8443") || s.Covers("svc.corp.test", "443") || s.Covers("svc.corp.test", "80") {
		t.Fatal("a host with a port covers that port only")
	}
	if got := s.Hosts(); len(got) != 1 || got[0] != "svc.corp.test:8443" {
		t.Fatalf("Hosts %q", got)
	}
	if r := s.Match("svc.corp.test", "8443", "GET", req(t, "/"), nil); r == nil || r.Stub != "stub#1" || r.Status != 200 {
		t.Fatalf("default name and status: %+v", r)
	}
}

func TestNilSet(t *testing.T) {
	var s *Set
	if s.Covers("a.test", "443") || s.Match("a.test", "443", "GET", req(t, "/"), nil) != nil || s.Hosts() != nil || s.Len() != 0 {
		t.Fatal("a nil set simulates nothing")
	}
}

func TestCompileRefuses(t *testing.T) {
	big := strings.Repeat("x", MaxBody+1)
	cases := map[string]Stub{
		"no host":           {},
		"ip":                {Match: Match{Host: "127.0.0.1"}},
		"ipv6":              {Match: Match{Host: "[::1]:443"}},
		"bad port":          {Match: Match{Host: "a.test:http"}},
		"port 0":            {Match: Match{Host: "a.test:0"}},
		"tld wildcard":      {Match: Match{Host: "*.com"}},
		"inner wildcard":    {Match: Match{Host: "a.*.test"}},
		"bare star":         {Match: Match{Host: "*"}},
		"empty label":       {Match: Match{Host: "a..test"}},
		"unicode":           {Match: Match{Host: "bücher.test"}},
		"path in host":      {Match: Match{Host: "a.test/x"}},
		"mirror":            {Match: Match{Host: "airbag.mirror"}},
		"method":            {Match: Match{Host: "a.test", Method: "GE T"}},
		"connect":           {Match: Match{Host: "a.test", Method: "connect"}},
		"relative path":     {Match: Match{Host: "a.test", Path: "v1"}},
		"query in path":     {Match: Match{Host: "a.test", Path: "/v1?x=1"}},
		"control in path":   {Match: Match{Host: "a.test", Path: "/v1\n"}},
		"host header":       {Match: Match{Host: "a.test", Headers: map[string]string{"host": "x"}}},
		"bad header name":   {Match: Match{Host: "a.test", Headers: map[string]string{"a b": "x"}}},
		"status 101":        {Match: Match{Host: "a.test"}, Respond: Respond{Status: 101}},
		"status 600":        {Match: Match{Host: "a.test"}, Respond: Respond{Status: 600}},
		"body with 204":     {Match: Match{Host: "a.test"}, Respond: Respond{Status: 204, Body: "x"}},
		"framing header":    {Match: Match{Host: "a.test"}, Respond: Respond{Headers: map[string]string{"content-length": "5"}}},
		"transfer encoding": {Match: Match{Host: "a.test"}, Respond: Respond{Headers: map[string]string{"Transfer-Encoding": "chunked"}}},
		"header injection":  {Match: Match{Host: "a.test"}, Respond: Respond{Headers: map[string]string{"X-A": "b\r\nSet-Cookie: c"}}},
		"header twice":      {Match: Match{Host: "a.test"}, Respond: Respond{Headers: map[string]string{"x-a": "1", "X-A": "2"}}},
		"body file unread":  {Match: Match{Host: "a.test"}, Respond: Respond{BodyFile: "x.json"}},
		"body too big":      {Match: Match{Host: "a.test"}, Respond: Respond{Body: big}},
		"delay too long":    {Match: Match{Host: "a.test"}, Respond: Respond{Delay: "11m"}},
		"negative delay":    {Match: Match{Host: "a.test"}, Respond: Respond{Delay: "-1s"}},
		"bad delay":         {Match: Match{Host: "a.test"}, Respond: Respond{Delay: "soon"}},
		"name with space":   {Name: "a b", Match: Match{Host: "a.test"}},
		"name with escape":  {Name: "a\x1b[31m", Match: Match{Host: "a.test"}},
	}
	for what, st := range cases {
		if _, err := Compile([]Stub{st}); err == nil {
			t.Errorf("%s: compiled", what)
		}
	}
	if _, err := Compile([]Stub{{Name: "x", Match: Match{Host: "a.test"}}, {Name: "x", Match: Match{Host: "b.test"}}}); err == nil {
		t.Error("two stubs with one name compiled")
	}
	many := make([]Stub, MaxStubs+1)
	for i := range many {
		many[i] = Stub{Match: Match{Host: "a.test"}}
	}
	if _, err := Compile(many); err == nil {
		t.Error("more than MaxStubs compiled")
	}
	total := []Stub{}
	for i := 0; i <= MaxTotalBody/MaxBody; i++ {
		total = append(total, Stub{Match: Match{Host: "a.test"}, Respond: Respond{Body: big[:MaxBody]}})
	}
	if _, err := Compile(total); err == nil {
		t.Error("bodies past MaxTotalBody compiled")
	}
}

func TestResponse(t *testing.T) {
	s := mustCompile(t, Stub{Name: "down", Match: Match{Host: "a.test"}, Respond: Respond{
		Status: 503, Headers: map[string]string{"retry-after": "1", "content-type": "application/json"}, Body: `{"error":"maintenance"}`, Delay: "1.5s",
	}})
	r := s.Match("a.test", "443", "GET", req(t, "/anything"), nil)
	if r == nil || r.Status != 503 || string(r.Body) != `{"error":"maintenance"}` || r.Delay != 1500*time.Millisecond ||
		r.Header.Get("Retry-After") != "1" || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%+v", r)
	}
}
