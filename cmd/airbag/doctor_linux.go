//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// cmdDoctor checks the kernel features airbag needs and prints the
// one-time fix for Ubuntu's restriction on user namespaces.
func cmdDoctor() error {
	ok := true
	check := func(name string, good bool, hint string) {
		mark := "ok  "
		if !good {
			mark, ok = "FAIL", false
		}
		fmt.Printf("%s %s\n", mark, name)
		if !good && hint != "" {
			fmt.Println("     " + strings.ReplaceAll(hint, "\n", "\n     "))
		}
	}

	var u unix.Utsname
	_ = unix.Uname(&u)
	rel := unix.ByteSliceToString(u.Release[:])
	var major, minor int
	_, _ = fmt.Sscanf(rel, "%d.%d", &major, &minor) // a release it cannot read fails the check as 0.0
	check("kernel "+rel+" (need 5.12+: overlay in user namespaces, mount_setattr)",
		major > 5 || (major == 5 && minor >= 12), "upgrade the kernel")

	fs, _ := os.ReadFile("/proc/filesystems")
	check("overlayfs available", strings.Contains(string(fs), "overlay"), "sudo modprobe overlay")

	restricted := false
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil {
		restricted = strings.TrimSpace(string(b)) == "1"
	}
	self, _ := os.Executable()
	check("unprivileged user namespaces allowed", !restricted, fmt.Sprintf(
		"AppArmor restricts them (Ubuntu 23.10+). Allow airbag once:\n"+
			"sudo tee /etc/apparmor.d/airbag >/dev/null <<'EOF'\n"+
			"abi <abi/4.0>,\ninclude <tunables/global>\n"+
			"profile airbag %s flags=(unconfined) {\n  userns,\n}\nEOF\n"+
			"sudo apparmor_parser -r /etc/apparmor.d/airbag", self))

	if !restricted {
		err := exec.CommandContext(context.Background(), "unshare", "--user", "--map-root-user", "--mount", "true").Run()
		check("can create a user + mount namespace", err == nil, "check kernel.unprivileged_userns_clone and user.max_user_namespaces")
	}
	// FUSE is optional: without it secret files are hidden rather than
	// served and tracked, so the session runs but cannot read them.
	if unix.Access("/dev/fuse", unix.W_OK) != nil {
		fmt.Println("note: /dev/fuse is not writable: .env and other secret files will be hidden from the agent " +
			"instead of tracked (install fuse3, or give your user access to /dev/fuse)")
	} else {
		fmt.Println("ok   /dev/fuse writable: reads of secret files are tracked")
	}
	if os.Getuid() == 0 {
		fmt.Println("note: running as root; Claude Code refuses --dangerously-skip-permissions as root, run airbag as your user")
	}
	reportKernelSysctls()
	if !ok {
		return fmt.Errorf("this machine is not ready")
	}
	return nil
}

// reportKernelSysctls prints, for information only, host sysctls that
// bear on the kernel surface. airbag already narrows most of this inside
// the sandbox; a hardened host is defense in depth, not a requirement,
// so none of this fails the check. Each line says whether airbag also
// covers it in the sandbox or whether it is host-only.
func reportKernelSysctls() {
	sysctls := []struct{ path, reason string }{
		{"/proc/sys/kernel/unprivileged_bpf_disabled", "1/2 blocks unprivileged bpf() host-wide; airbag refuses bpf in the sandbox"},
		{"/proc/sys/kernel/io_uring_disabled", "2 disables io_uring host-wide; airbag refuses it in the sandbox"},
		{"/proc/sys/kernel/perf_event_paranoid", "higher limits perf_event_open; airbag refuses it in the sandbox"},
		{"/proc/sys/kernel/yama/ptrace_scope", "1+ limits ptrace across processes; airbag relies on the user-namespace boundary and dumpable=0"},
		{"/proc/sys/kernel/kptr_restrict", "1/2 hides kernel pointers in /proc (host-wide; not changed inside the sandbox)"},
		{"/proc/sys/kernel/dmesg_restrict", "1 keeps the kernel log from unprivileged readers; airbag also refuses syslog() and hides /dev/kmsg in the sandbox"},
		{"/proc/sys/dev/tty/legacy_tiocsti", "0 disables TIOCSTI host-wide; airbag refuses it in the sandbox"},
	}
	printed := false
	for _, s := range sysctls {
		b, err := os.ReadFile(s.path)
		if err != nil {
			continue // not present on this kernel
		}
		if !printed {
			fmt.Println("host kernel sysctls (informational; airbag narrows most of this inside the sandbox):")
			printed = true
		}
		name := strings.TrimPrefix(s.path, "/proc/sys/")
		fmt.Printf("     %-40s = %-3s  %s\n", strings.ReplaceAll(name, "/", "."), strings.TrimSpace(string(b)), s.reason)
	}
}
