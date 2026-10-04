//go:build darwin

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var checks = []func(*probe) Result{
	checkSeatbelt,
	checkViolationLog,
	checkNFSMount,
	checkNFSSpeed,
	checkGitAtMount,
	checkClone,
	checkTLS,
}

func systemVersion() string {
	v, _ := run(5*time.Second, "", "/usr/bin/sw_vers", "-productVersion")
	m, _ := run(5*time.Second, "", "/usr/bin/uname", "-m")
	return "macOS " + strings.TrimSpace(v) + " " + strings.TrimSpace(m)
}

// cleanup unmounts the export and stops its server. It asks the kernel
// whether the mount point is still one rather than trusting p.mounted: a
// mount_nfs killed by Ctrl-C or its timeout can have mounted anyway, and
// two attempts can stack. When neither umount nor diskutil can unmount
// it, the mount and the server stay and the failure is returned.
func (p *probe) cleanup() error {
	for i := 0; p.mnt != "" && isMount(p.mnt); i++ {
		if i == 3 {
			return fmt.Errorf("%s is still mounted after three unmounts", p.mnt)
		}
		if _, err := run(20*time.Second, "", "/sbin/umount", p.mnt); err != nil {
			if out, err := run(20*time.Second, "", "/usr/sbin/diskutil", "unmount", "force", p.mnt); err != nil {
				return fmt.Errorf("cannot unmount %s: %v: %s", p.mnt, err, firstLine(out))
			}
		}
	}
	p.mounted = false
	if p.srv != nil {
		_ = p.srv.Close()
	}
	return nil
}

// isMount reports whether p is a mount point: statfs names it as the
// directory its filesystem is mounted on.
func isMount(p string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return false
	}
	return unix.ByteSliceToString(st.Mntonname[:]) == p
}

// S1: a deny-first profile around a shell: writes only where allowed,
// credentials unreadable, the network only on the proxy's localhost port.
func checkSeatbelt(p *probe) Result {
	r := Result{ID: "S1", Name: "Seatbelt profile around a shell"}
	ws, secret := filepath.Join(p.dir, "ws"), filepath.Join(p.dir, "secret")
	for _, d := range []string{ws, secret} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fail(r, err)
		}
	}
	if err := writeFile(filepath.Join(secret, "token"), "s3cret\n"); err != nil {
		return fail(r, err)
	}
	px, err := startProxy()
	if err != nil {
		return fail(r, err)
	}
	defer px.Close()
	// A second local listener on a port the profile does not allow. It is
	// reachable from here, so a refusal inside the profile is Seatbelt's
	// and not a network that happens to be down.
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fail(r, err)
	}
	defer other.Close()
	go func() {
		for {
			c, err := other.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if c, err := net.DialTimeout("tcp", other.Addr().String(), 3*time.Second); err != nil {
		return fail(r, fmt.Errorf("the control listener is not reachable outside the profile: %w", err))
	} else {
		c.Close()
	}
	otherPort := other.Addr().(*net.TCPAddr).Port
	// The internet is judged only where it is reachable from here: offline
	// or behind a proxy, "no" inside the profile would prove nothing.
	internet := false
	if !p.opts.noNet {
		if c, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second); err == nil {
			c.Close()
			internet = true
		}
	}
	p.tag = fmt.Sprintf("airbag-macprobe-%d", time.Now().UnixNano())
	homeFile := filepath.Join(p.home, "."+p.tag)
	// The home directory must be writable outside the profile, or "no"
	// inside it would say nothing about Seatbelt.
	homeWritable := writeFile(homeFile, "x\n") == nil
	_ = os.Remove(homeFile)
	prof := Profile{Tag: p.tag, Write: []string{ws}, NoRead: []string{secret}, Ports: []int{px.Port()}}
	script := fmt.Sprintf(`try() { if "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }
echo "write-workspace=$(try sh -c 'echo x > %[1]s/f')"
echo "write-home=$(try sh -c 'echo x > %[2]s')"
echo "read-secret=$(try cat %[3]s/token)"
echo "read-system=$(try cat /etc/hosts)"
echo "connect-other-port=$(try /usr/bin/nc -z -G 3 127.0.0.1 %[5]d)"
echo "connect-proxy=$(try /usr/bin/nc -z -G 3 127.0.0.1 %[4]d)"
`, shq(ws), shq(homeFile), shq(secret), px.Port(), otherPort)
	if internet {
		script += "echo \"connect-internet=$(try /usr/bin/nc -z -G 3 1.1.1.1 443)\"\n"
	}
	out, err := run(60*time.Second, ws, "/usr/bin/sandbox-exec", "-p", prof.String(), "/bin/sh", "-c", script)
	_ = os.Remove(homeFile) // in case the profile let it through
	r.Detail = out
	if p.opts.verbose {
		r.Detail += "\nprofile:\n" + prof.String()
	}
	if err != nil && !strings.Contains(out, "=") {
		r.Status, r.Reason = Fail, "sandbox-exec did not run: "+firstLine(out+" "+err.Error())
		return r
	}
	want := map[string]string{
		"write-workspace": "yes", "write-home": "no", "read-secret": "no",
		"read-system": "yes", "connect-other-port": "no", "connect-proxy": "yes",
	}
	if internet {
		want["connect-internet"] = "no"
	}
	if !homeWritable {
		delete(want, "write-home")
	}
	bad := mismatches(markers(out), want)
	if len(bad) > 0 {
		r.Status, r.Reason = Fail, strings.Join(bad, ", ")
		return r
	}
	r.Status, r.Reason = Pass, "writes only to the workspace, credentials unreadable, network only to the proxy port"
	if !internet {
		r.Reason += " (the internet is not reachable from here, so that was shown on a second local port only)"
	}
	return r
}

// S2: the denials from S1 can be read from the unified log without admin
// rights, so airbag could list blocked operations in review.
func checkViolationLog(p *probe) Result {
	r := Result{ID: "S2", Name: "Sandbox violation log readable"}
	if p.tag == "" {
		r.Status, r.Reason = Info, "skipped: S1 did not run"
		return r
	}
	time.Sleep(2 * time.Second) // the log is written asynchronously
	file := "." + p.tag         // S1's denied write in the home directory
	pred := fmt.Sprintf(`eventMessage CONTAINS %q`, file)
	out, err := run(90*time.Second, "", "/usr/bin/log", "show", "--last", "5m", "--style", "ndjson", "--predicate", pred)
	r.Detail = clip(out, 4000)
	if err != nil {
		r.Status, r.Reason = Fail, "log show failed: "+firstLine(out+" "+err.Error())
		return r
	}
	hits := violationLines(out, file)
	if len(hits) == 0 {
		r.Status, r.Reason = Fail, "no log line names the denied path (redacted as <private>, or not logged)"
		return r
	}
	r.Status = Pass
	r.Reason = fmt.Sprintf("%d line(s) name the denied write, e.g. %s", len(hits), clip(hits[0], 160))
	return r
}

// N1: an NFSv3 export from a server in this process, on a localhost port,
// mounted with the built-in mount_nfs by a regular user.
func checkNFSMount(p *probe) Result {
	r := Result{ID: "N1", Name: "NFS mount from localhost without root"}
	export := filepath.Join(p.dir, "export")
	p.mnt = filepath.Join(p.dir, "mnt")
	for _, d := range []string{export, p.mnt} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fail(r, err)
		}
	}
	if err := writeFile(filepath.Join(export, "hello.txt"), "hi\n"); err != nil {
		return fail(r, err)
	}
	srv, err := startNFS(export)
	if err != nil {
		return fail(r, err)
	}
	p.srv = srv
	var tried []string
	for _, o := range []string{"nolocks", "locallocks"} {
		opts := fmt.Sprintf("%s,vers=3,tcp,port=%d,mountport=%d,noresvport,soft,timeo=50,retrans=2", o, srv.Port(), srv.Port())
		out, err := run(45*time.Second, "", "/sbin/mount_nfs", "-o", opts, "127.0.0.1:/", p.mnt)
		tried = append(tried, fmt.Sprintf("mount_nfs -o %s: %s", opts, orNone(strings.TrimSpace(out+" "+errString(err)))))
		if err == nil || isMount(p.mnt) {
			p.mounted = true
			break
		}
	}
	r.Detail = strings.Join(tried, "\n")
	if !p.mounted {
		r.Status, r.Reason = Fail, "mount_nfs refused as a regular user (see detail)"
		return r
	}
	b, err := os.ReadFile(filepath.Join(p.mnt, "hello.txt"))
	if err != nil || string(b) != "hi\n" {
		r.Status, r.Reason = Fail, fmt.Sprintf("mounted, but reading through it failed: %q %v", b, err)
		return r
	}
	steps := []func() error{
		func() error { return writeFile(filepath.Join(p.mnt, "new.txt"), "new\n") },
		func() error { return os.Rename(filepath.Join(p.mnt, "new.txt"), filepath.Join(p.mnt, "renamed.txt")) },
		func() error { return os.MkdirAll(filepath.Join(p.mnt, "a", "b"), 0o755) },
		func() error { return os.Remove(filepath.Join(p.mnt, "hello.txt")) },
	}
	for i, s := range steps {
		if err := s(); err != nil {
			r.Status, r.Reason = Fail, fmt.Sprintf("mounted and readable, but write step %d failed: %v", i+1, err)
			return r
		}
	}
	b, err = os.ReadFile(filepath.Join(export, "renamed.txt"))
	st, derr := os.Stat(filepath.Join(export, "a", "b"))
	_, gerr := os.Lstat(filepath.Join(export, "hello.txt"))
	if err != nil || string(b) != "new\n" || derr != nil || !st.IsDir() || !errors.Is(gerr, os.ErrNotExist) {
		r.Status, r.Reason = Fail, "a change through the mount did not reach the export as made"
		return r
	}
	mnt, _ := run(10*time.Second, "", "/sbin/mount")
	for _, l := range strings.Split(mnt, "\n") {
		if strings.Contains(l, p.mnt) {
			r.Detail += "\n" + l
		}
	}
	r.Status, r.Reason = Pass, "mounted as a regular user; read, write, rename, mkdir and delete reach the export"
	return r
}

// N2: how much slower a node_modules-sized tree is through the mount.
func checkNFSSpeed(p *probe) Result {
	r := Result{ID: "N2", Name: fmt.Sprintf("NFS speed, %d small files", p.opts.files)}
	if !p.mounted {
		r.Status, r.Reason = Info, "skipped: not mounted"
		return r
	}
	direct := filepath.Join(p.dir, "direct")
	viaNFS := filepath.Join(p.mnt, "tree")
	cd, err := timed(func() error { return makeTree(direct, p.opts.files) })
	if err != nil {
		return fail(r, err)
	}
	cn, err := timed(func() error { return makeTree(viaNFS, p.opts.files) })
	if err != nil {
		return fail(r, fmt.Errorf("creating through the mount: %w", err))
	}
	wd, _ := timed(func() error { _, err := countFiles(direct); return err })
	var n int
	wn, err := timed(func() error { var e error; n, e = countFiles(viaNFS); return e })
	if err != nil || n != p.opts.files {
		r.Status, r.Reason = Fail, fmt.Sprintf("walk through the mount saw %d of %d files: %v", n, p.opts.files, err)
		return r
	}
	r.Status = Info
	r.Reason = fmt.Sprintf("create %.1fx and walk %.1fx slower than the local disk", cn.Seconds()/cd.Seconds(), wn.Seconds()/wd.Seconds())
	r.Numbers = []Number{
		{"create_direct", seconds(cd), "s"}, {"create_nfs", seconds(cn), "s"},
		{"walk_direct", seconds(wd), "s"}, {"walk_nfs", seconds(wn), "s"},
	}
	return r
}

// N3: git works in a repository at the mount path; the agents' versions
// are noted if they are installed.
func checkGitAtMount(p *probe) Result {
	r := Result{ID: "N3", Name: "git in a repository on the mount"}
	if !p.mounted {
		r.Status, r.Reason = Info, "skipped: not mounted"
		return r
	}
	repo := filepath.Join(p.mnt, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		return fail(r, err)
	}
	var log []string
	env := gitEnv(os.Environ())
	git := func(args ...string) (string, error) {
		return runEnv(60*time.Second, repo, env, "git", append(append([]string{}, gitArgs...), args...)...)
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"commit", "-q", "--allow-empty", "-m", "empty"},
	} {
		out, err := git(args...)
		log = append(log, "git "+strings.Join(args, " ")+": "+orNone(strings.TrimSpace(out+" "+errString(err))))
		if err != nil {
			r.Status, r.Reason, r.Detail = Fail, "git "+args[0]+" failed", strings.Join(log, "\n")
			return r
		}
	}
	if err := writeFile(filepath.Join(repo, "a.txt"), "a\n"); err != nil {
		return fail(r, err)
	}
	for _, args := range [][]string{
		{"add", "-A"},
		{"commit", "-qm", "a"},
		{"status", "--porcelain"},
		{"log", "--oneline"},
	} {
		out, err := git(args...)
		log = append(log, "git "+strings.Join(args, " ")+": "+orNone(strings.TrimSpace(out+" "+errString(err))))
		if err != nil {
			r.Status, r.Reason, r.Detail = Fail, "git "+args[0]+" failed", strings.Join(log, "\n")
			return r
		}
	}
	for _, agent := range []string{"claude", "codex"} {
		if path, err := exec.LookPath(agent); err == nil {
			out, err := run(30*time.Second, repo, path, "--version")
			log = append(log, agent+" --version at the mount: "+orNone(strings.TrimSpace(out+" "+errString(err))))
		}
	}
	r.Detail = strings.Join(log, "\n")
	r.Status, r.Reason = Pass, "init, add, commit, status and log work at the mount path"
	return r
}

// C1: an APFS clone of a tree (clonefile) as a cheaper branch than NFS:
// instant copy-on-write, no server, at the cost of a different path.
// clonefile(2) is called directly: `cp -c` falls back to a plain copy
// where cloning is not supported, so its success would not prove a clone
// happened, and its timing would be a copy's.
func checkClone(p *probe) Result {
	r := Result{ID: "C1", Name: fmt.Sprintf("APFS clone of a %d-file tree", p.opts.files)}
	src := filepath.Join(p.dir, "clone-src")
	if err := makeTree(src, p.opts.files); err != nil {
		return fail(r, err)
	}
	cl, cp := filepath.Join(p.dir, "clone-c"), filepath.Join(p.dir, "clone-plain")
	tc, err := timed(func() error { return unix.Clonefile(src, cl, unix.CLONE_NOFOLLOW) })
	switch {
	case errors.Is(err, unix.ENOTSUP):
		r.Status, r.Reason = Fail, "this filesystem cannot clone (not APFS?); airbag's cp -c would make a full copy here"
		return r
	case err != nil:
		r.Status, r.Reason = Fail, "clonefile failed: "+err.Error()
		return r
	}
	tp, err := timed(func() error { _, err := run(5*time.Minute, "", "/bin/cp", "-R", src, cp); return err })
	if err != nil {
		return fail(r, err)
	}
	// What the prototype runs: cp clones file by file, so it pays per
	// file where one clonefile call pays once for the tree.
	tcc, err := timed(func() error {
		_, err := run(5*time.Minute, "", "/bin/cp", "-c", "-R", src, filepath.Join(p.dir, "clone-cp"))
		return err
	})
	if err != nil {
		return fail(r, fmt.Errorf("cp -c -R: %w", err))
	}
	f := filepath.Join("node_modules", "pkg-000", "v0", "lib", "f00.js")
	if err := writeFile(filepath.Join(cl, f), "changed\n"); err != nil {
		return fail(r, err)
	}
	if b, _ := os.ReadFile(filepath.Join(src, f)); string(b) == "changed\n" {
		r.Status, r.Reason = Fail, "a write to the clone changed the source"
		return r
	}
	r.Status = Pass
	r.Reason = fmt.Sprintf("clone is independent of the source; cp -c -R (as the prototype) %.1fx and one clonefile %.1fx faster than cp -R",
		tp.Seconds()/tcc.Seconds(), tp.Seconds()/tc.Seconds())
	r.Numbers = []Number{{"clonefile", seconds(tc), "s"}, {"cp_c", seconds(tcc), "s"}, {"copy", seconds(tp), "s"}}
	return r
}

// T1: a Go program inside the profile verifies TLS through the proxy
// without the trustd service; with it as the comparison.
func checkTLS(p *probe) Result {
	r := Result{ID: "T1", Name: "Go TLS through the proxy without trustd"}
	if p.opts.noNet {
		r.Status, r.Reason = Info, "skipped: -no-net"
		return r
	}
	exe, err := os.Executable()
	if err != nil {
		return fail(r, err)
	}
	px, err := startProxy()
	if err != nil {
		return fail(r, err)
	}
	defer px.Close()
	attempt := func(trustd bool) (bool, string) {
		prof := Profile{Write: []string{p.dir}, Ports: []int{px.Port()}, Trustd: trustd}
		cmd := exec.Command("/usr/bin/sandbox-exec", "-p", prof.String(), exe, tlsClientArg, "https://proxy.golang.org/")
		cmd.Env = append(viaProxy(os.Environ(), px.Port()), "TMPDIR="+p.dir)
		out, _ := cmd.CombinedOutput()
		return strings.Contains(string(out), "tls=ok"), strings.TrimSpace(string(out))
	}
	okWithout, outWithout := attempt(false)
	okWith, outWith := attempt(true)
	r.Detail = "without trustd: " + outWithout + "\nwith trustd: " + outWith + "\nproxy saw: " + strings.Join(px.Seen(), ", ")
	switch {
	case okWithout:
		r.Status, r.Reason = Pass, "certificate verified without trustd"
	case okWith:
		r.Status, r.Reason = Fail, "works only with trustd allowed (as sandbox-runtime reports)"
	default:
		r.Status, r.Reason = Fail, "fails with and without trustd: "+firstLine(outWith)
	}
	return r
}

func fail(r Result, err error) Result {
	r.Status, r.Reason = Fail, err.Error()
	return r
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
