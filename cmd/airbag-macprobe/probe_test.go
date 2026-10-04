package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
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
	path, err := srv.Arm()
	if err != nil {
		t.Fatal(err)
	}
	target, err := nfsMount(t, srv, path)
	if err != nil {
		t.Fatal(err)
	}
	if b := readNFS(t, target, "/hello.txt"); b != "hi\n" {
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

func TestHomeDir(t *testing.T) {
	for _, h := range []string{"", "/", "relative/dir"} {
		t.Setenv("HOME", h)
		got, err := homeDir()
		if err == nil && (!filepath.IsAbs(got) || got == "/") {
			t.Errorf("HOME=%q: homeDir() = %q", h, got)
		}
	}
	t.Setenv("HOME", "/Users/me")
	if got, err := homeDir(); err != nil || got != "/Users/me" {
		t.Errorf("HOME=/Users/me: homeDir() = %q, %v", got, err)
	}
}

func TestViolationLines(t *testing.T) {
	const f = ".airbag-macprobe-1"
	out := `Filtering the log data using "eventMessage CONTAINS \".airbag-macprobe-1\""
{"eventMessage":"Sandbox: sh(42) deny(1) file-write-create /Users/me/.airbag-macprobe-1","subsystem":""}
{"eventMessage":"Sandbox: sh(42) deny(1) file-write-create <private>"}
{"eventMessage":"opened /Users/me/.airbag-macprobe-1"}
{"count":3,"finished":1}`
	hits := violationLines(out, f)
	if len(hits) != 1 || !strings.Contains(hits[0], "deny(1) file-write-create /Users/me/"+f) {
		t.Fatalf("hits = %q", hits)
	}
	if hits := violationLines(`Filtering the log data using "eventMessage CONTAINS \".airbag-macprobe-1\""`, f); len(hits) != 0 {
		t.Fatalf("the header counted: %q", hits)
	}
}

func TestGitEnv(t *testing.T) {
	env := gitEnv([]string{"HOME=/h", "GIT_DIR=/real/.git", "GIT_WORK_TREE=/real", "PATH=/bin"})
	want := []string{"HOME=/h", "PATH=/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	if strings.Join(env, " ") != strings.Join(want, " ") {
		t.Fatalf("got %q, want %q", env, want)
	}
}

// The export holds every path inside its directory: through "..", an
// absolute path or a symlink that a client of the export made (the
// probe's mount, or a process that mounted the armed path first),
// nothing outside can be read, written or changed.
func TestExportStaysInside(t *testing.T) {
	base := t.TempDir()
	dir, outside := filepath.Join(base, "export"), filepath.Join(base, "outside")
	for _, d := range []string{dir, outside} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(outside, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	fs := exportFS(dir)
	for _, name := range []string{"../outside", outside, "link"} {
		ents, _ := fs.ReadDir(name)
		for _, e := range ents {
			if e.Name() == "secret" && e.Size() == int64(len("s3cret")) {
				t.Errorf("ReadDir(%q) listed the file outside the export", name)
			}
		}
	}
	for i, name := range []string{"../outside/secret", secret, "link/secret"} {
		if fi, err := fs.Stat(name); err == nil && fi.Size() == int64(len("s3cret")) {
			t.Errorf("Stat(%q) saw the file outside the export", name)
		}
		if f, err := fs.Open(name); err == nil {
			b, _ := io.ReadAll(f)
			f.Close()
			if string(b) == "s3cret" {
				t.Errorf("Open(%q) read the file outside the export", name)
			}
		}
		if f, err := fs.Create(name); err == nil {
			_, _ = f.Write([]byte("x"))
			f.Close()
		}
		ch := fs.(billy.Change)
		_ = ch.Chmod(name, 0o666)
		_ = ch.Chtimes(name, time.Unix(0, 0), time.Unix(0, 0))
		// The changes BoundOS took over in v5.9: none may move, replace
		// or remove anything outside.
		mine := fmt.Sprintf("mine%d", i)
		if err := os.WriteFile(filepath.Join(dir, mine), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = fs.Rename(name, fmt.Sprintf("moved%d", i))
		_ = fs.Rename(mine, name)
		_ = fs.Remove(name)
	}
	for i, name := range []string{"../outside/sub", sub, "link/sub", "../outside", "link"} {
		_ = fs.Remove(name)
		// go-nfs calls MkdirAll for MKDIR and Symlink for SYMLINK.
		_ = fs.MkdirAll(filepath.Join(name, "made"), 0o755)
		_ = fs.Symlink("/", filepath.Join(name, fmt.Sprintf("planted%d", i)))
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 2 {
		t.Errorf("entries outside the export: %v, want secret and sub", ents)
	}
	if ents, _ := os.ReadDir(sub); len(ents) != 0 {
		t.Errorf("entries in the directory outside: %v, want none", ents)
	}
	st, err := os.Stat(secret)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(secret); string(b) != "s3cret" || st.Mode().Perm() != 0o600 || st.ModTime().Unix() == 0 {
		t.Fatalf("the file outside changed: %q %v %v", b, st.Mode(), st.ModTime())
	}
	if _, err := os.Stat(sub); err != nil {
		t.Fatalf("the directory outside is gone: %v", err)
	}
}

func TestPlatformTrust(t *testing.T) {
	env, removed := platformTrust([]string{"HOME=/h", "SSL_CERT_FILE=/etc/ssl/cert.pem", "SSL_CERT_DIR=/d", "SSL_CERT_FILES=x"})
	if strings.Join(env, " ") != "HOME=/h SSL_CERT_FILES=x" || strings.Join(removed, " ") != "SSL_CERT_FILE SSL_CERT_DIR" {
		t.Fatalf("env %q, removed %q", env, removed)
	}
}

// nfsMount sends srv a MOUNT for path, on a connection of its own,
// through an NFS client library.
func nfsMount(t *testing.T, srv *nfsServer, path string) (*nfsc.Target, error) {
	t.Helper()
	c, err := rpc.DialTCP("tcp", srv.l.Addr().String(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	m := nfsc.Mount{Client: c}
	return m.Mount(path, rpc.AuthNull)
}

func readNFS(t *testing.T, target *nfsc.Target, name string) string {
	t.Helper()
	f, err := target.Open(name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	return string(b)
}

// refused fails t unless err is the server's access error for a MOUNT.
func refused(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "MNT3ERR_ACCES") {
		t.Errorf("%s: want MNT3ERR_ACCES, got %v", what, err)
	}
}

// The server grants one MOUNT: the first for the armed path, which may
// end in one "/". It refuses one before Arm, one for any other path, a
// later one for the armed path, and one from a connection opened before
// Arm; it counts those refusals apart; and it does not arm again after
// the grant.
func TestNFSGrantsOneMount(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv, err := startNFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	_, err = nfsMount(t, srv, "/")
	refused(t, "Mount(/) before Arm", err)
	early, err := rpc.DialTCP("tcp", srv.l.Addr().String(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer early.Close()
	path, err := srv.Arm()
	if err != nil {
		t.Fatal(err)
	}
	others := []string{"/wrong", "/", path + "//", path[:len(path)-1], path[:len(path)-1] + "/", strings.ToLower(path)}
	for _, p := range others {
		_, err := nfsMount(t, srv, p)
		refused(t, "Mount("+p+")", err)
	}
	target, err := nfsMount(t, srv, path+"/")
	if err != nil {
		t.Fatalf("the armed path with one trailing / was refused: %v", err)
	}
	if b := readNFS(t, target, "/hello.txt"); b != "hi\n" {
		t.Fatalf("read %q", b)
	}
	_, err = nfsMount(t, srv, path)
	refused(t, "a second Mount of the armed path", err)
	_, err = nfsMount(t, srv, path+"/")
	refused(t, "a second Mount of the armed path with a trailing /", err)
	m := nfsc.Mount{Client: early}
	_, err = m.Mount(path, rpc.AuthNull)
	refused(t, "Mount of the armed path on a connection opened before Arm", err)
	if p, err := srv.Arm(); err == nil {
		t.Errorf("Arm after the grant gave %q", p)
	}
	if late, other := srv.Refused(); late != 3 || other != 1+len(others) {
		t.Errorf("Refused() = %d late, %d other; want 3, %d", late, other, 1+len(others))
	}
}

// After Seal the client that is already connected (the probe's mount)
// still works, and no new one gets in.
func TestNFSSeal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv, err := startNFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	path, err := srv.Arm()
	if err != nil {
		t.Fatal(err)
	}
	target, err := nfsMount(t, srv, path)
	if err != nil {
		t.Fatal(err)
	}
	srv.Seal()
	if b := readNFS(t, target, "/hello.txt"); b != "hi\n" {
		t.Fatalf("the open client lost the export: read %q", b)
	}
	if c2, err := net.DialTimeout("tcp", srv.l.Addr().String(), 2*time.Second); err == nil {
		c2.Close()
		t.Fatal("a new client connected after Seal")
	}
}

// When the probe's mount does not come up, Close ends every connection
// the server took: an idle one is cut off, the client that was granted
// the export reads nothing more, and no new client connects.
func TestNFSCloseDropsConnections(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv, err := startNFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := srv.l.Addr().String()
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	path, err := srv.Arm()
	if err != nil {
		t.Fatal(err)
	}
	// The server accepts in order, so the idle connection, dialled
	// first, is taken by the time this mount is answered.
	target, err := nfsMount(t, srv, path)
	if err != nil {
		t.Fatal(err)
	}
	if b := readNFS(t, target, "/hello.txt"); b != "hi\n" {
		t.Fatalf("read %q", b)
	}
	_ = srv.Close()
	_ = idle.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := idle.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("an idle connection stayed open after Close (read: %v)", err)
	}
	// The client library reconnects and retries for about 10 s before it
	// gives up, so a read that has not come back within 2 s counts as one
	// that got nothing.
	got := make(chan error, 1)
	go func() {
		f, err := target.Open("/hello.txt")
		if err == nil {
			f.Close()
		}
		got <- err
	}()
	select {
	case err := <-got:
		if err == nil {
			t.Error("the client granted the export still reads it after Close")
		}
	case <-time.After(2 * time.Second):
	}
	if c, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		c.Close()
		t.Error("a new client connected after Close")
	}
}

// T1 judges the profile only when the control outside it got through;
// otherwise it is skipped, whatever the two requests inside said.
func TestTLSVerdict(t *testing.T) {
	ok := tlsTry{ok: true, out: "tls=ok 200 OK"}
	no := tlsTry{out: "tls=error x509: certificate signed by unknown authority"}
	down := tlsTry{out: "tls=error Get \"https://proxy.golang.org/\": Forbidden\nmore"}
	for _, c := range []struct {
		control, without, with tlsTry
		status                 Status
		reason                 string
	}{
		{ok, ok, ok, Pass, "certificate verified without trustd"},
		{ok, ok, no, Pass, "certificate verified without trustd"},
		{ok, no, ok, Fail, "works only with trustd allowed (as sandbox-runtime reports)"},
		{ok, no, no, Fail, "fails with and without trustd: " + no.out},
		{down, no, no, Info, "skipped: the control request did not get through: tls=error Get \"https://proxy.golang.org/\": Forbidden"},
		{down, tlsTry{}, tlsTry{}, Info, "skipped: the control request did not get through: tls=error Get \"https://proxy.golang.org/\": Forbidden"},
		{down, ok, ok, Info, "skipped: the control request did not get through: tls=error Get \"https://proxy.golang.org/\": Forbidden"},
		{tlsTry{}, tlsTry{}, tlsTry{}, Info, "skipped: the control request did not get through: none"},
	} {
		s, r := tlsVerdict(c.control, c.without, c.with)
		if s != c.status || r != c.reason {
			t.Errorf("tlsVerdict(%v, %v, %v) = %s %q, want %s %q", c.control.ok, c.without.ok, c.with.ok, s, r, c.status, c.reason)
		}
	}
}
