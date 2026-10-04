package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nfsc "github.com/willscott/go-nfs-client/nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"
)

func TestProfile(t *testing.T) {
	p := Profile{Tag: `t"1`, Write: []string{"/private/tmp/ws"}, NoRead: []string{"/Users/me/.ssh"}, Ports: []int{3128}}
	s := p.String()
	for _, want := range []string{
		`(deny default (with message "t\"1"))`,
		`(allow file-write* (subpath "/private/tmp/ws"))`,
		`(deny file-read* (subpath "/Users/me/.ssh"))`,
		`(allow network-outbound (remote ip "localhost:3128"))`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("profile lacks %s:\n%s", want, s)
		}
	}
	// A read denial must follow the blanket read allowance: the last
	// matching rule wins.
	if strings.Index(s, "(allow file-read*)") > strings.Index(s, "(deny file-read*") {
		t.Error("read denial comes before the allowance")
	}
	if strings.Contains(s, trustdService) {
		t.Error("trustd allowed by default")
	}
	p.Trustd = true
	if !strings.Contains(p.String(), trustdService) {
		t.Error("Trustd: service missing")
	}
	if strings.Count(Profile{}.String(), "network-outbound") != 0 {
		t.Error("network allowed without ports")
	}
}

func TestReport(t *testing.T) {
	rep := &Report{Probe: "p"}
	rep.Add(Result{ID: "S1", Name: "seatbelt", Status: Pass, Reason: "ok"})
	rep.Add(Result{ID: "N2", Name: "speed", Status: Info, Reason: "slow", Numbers: []Number{{"create_nfs", 4.2123, "s"}, {"n", 5000, ""}}})
	rep.Add(Result{ID: "N1", Name: "mount", Status: Fail, Reason: "refused", Detail: "line1\nline2"})
	if rep.Summary != (Summary{Pass: 1, Fail: 1, Info: 1}) {
		t.Fatalf("summary %+v", rep.Summary)
	}
	if got := rep.Results[1].Line(); got != "INFO N2   speed: slow [create_nfs=4.21s n=5000]" {
		t.Errorf("line %q", got)
	}
	var b bytes.Buffer
	writeText(&b, rep, false)
	if !strings.Contains(b.String(), "          | line2") || strings.Count(b.String(), "|") != 2 {
		t.Errorf("text:\n%s", b.String())
	}
	r := redact(Result{Reason: "/var/folders/x/T/airbag-macprobe-1/mnt", Detail: "/Users/me/x"},
		strings.NewReplacer("/var/folders/x/T/airbag-macprobe-1", "$TMP", "/Users/me", "~"))
	if r.Reason != "$TMP/mnt" || r.Detail != "~/x" {
		t.Errorf("redact %+v", r)
	}
}

func TestMarkers(t *testing.T) {
	got := markers("write-home=no\nnoise line\nread-secret=yes\n")
	bad := mismatches(got, map[string]string{"write-home": "no", "read-secret": "no", "connect-proxy": "yes"})
	if strings.Join(bad, ";") != "connect-proxy=none (want yes);read-secret=yes (want no)" {
		t.Errorf("mismatches %v", bad)
	}
}

func TestTree(t *testing.T) {
	d := t.TempDir()
	if err := makeTree(d, 260); err != nil {
		t.Fatal(err)
	}
	if n, err := countFiles(d); err != nil || n != 260 {
		t.Fatalf("count %d %v", n, err)
	}
}

func TestProxy(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			_, _ = io.Copy(c, c)
			c.Close()
		}
	}()
	px, err := startProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()
	c, err := net.Dial("tcp", px.l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	target := echo.Addr().String()
	_, _ = io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT %v %v", resp, err)
	}
	_, _ = io.WriteString(c, "ping\n")
	if l, _ := br.ReadString('\n'); l != "ping\n" {
		t.Fatalf("echo %q", l)
	}
	if s := px.Seen(); len(s) != 1 || s[0] != target {
		t.Errorf("seen %v", s)
	}
}

// The NFS server, through an NFS client library instead of a mount:
// what mount_nfs on a Mac would talk to.
func TestNFSServer(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv, err := startNFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	c, err := rpc.DialTCP("tcp", srv.l.Addr().String(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m := nfsc.Mount{Client: c}
	target, err := m.Mount("/", rpc.AuthNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Unmount() }()
	f, err := target.Open("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "hi\n" {
		t.Fatalf("read %q", b)
	}
	w, err := target.OpenFile("/new.txt", 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("new"))
	w.Close()
	if got, _ := os.ReadFile(filepath.Join(dir, "new.txt")); string(got) != "new" {
		t.Fatalf("export has %q", got)
	}
	if _, err := target.Mkdir("/a", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := target.Remove("/hello.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "hello.txt")); !os.IsNotExist(err) {
		t.Fatal("remove did not reach the export")
	}
}

func TestViaProxy(t *testing.T) {
	env := viaProxy([]string{"HOME=/h", "NO_PROXY=*", "no_proxy=proxy.golang.org", "https_proxy=http://other:1", "HTTP_PROXY=http://other:2", "PATH=/bin"}, 3128)
	want := []string{"HOME=/h", "PATH=/bin", "HTTPS_PROXY=http://127.0.0.1:3128"}
	if strings.Join(env, " ") != strings.Join(want, " ") {
		t.Fatalf("got %q, want %q", env, want)
	}
}
