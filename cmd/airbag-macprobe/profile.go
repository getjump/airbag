package main

import (
	"fmt"
	"strings"
)

// Profile is a deny-first Seatbelt profile of the kind docs/macos.md plans
// around the agent. Everything is denied except what a shell and a Go
// program need to start, reading files outside NoRead, writing under
// Write, and connecting to the localhost ports in Ports.
//
// Paths must be resolved (/private/var/..., not /var/...): Seatbelt
// matches the real path of a file.
type Profile struct {
	Tag    string   // added to every denial, to find it in the violation log
	Write  []string // directories the sandbox may write
	NoRead []string // directories it may not read, such as credentials
	Ports  []int    // localhost TCP ports it may connect to (airbag's proxy)
	Trustd bool     // allow com.apple.trustd.agent, which Go's platform TLS verifier uses
}

// baseMach are the mach services the profile allows, after Claude Code's
// sandbox-runtime. trustd is not among them: see Profile.Trustd.
var baseMach = []string{
	"com.apple.audio.systemsoundserver",
	"com.apple.distributed_notifications@Uv3",
	"com.apple.FontObjectsServer",
	"com.apple.fonts",
	"com.apple.logd",
	"com.apple.lsd.mapdb",
	"com.apple.PowerManagement.control",
	"com.apple.system.logger",
	"com.apple.system.notification_center",
	"com.apple.system.opendirectoryd.libinfo",
	"com.apple.system.opendirectoryd.membership",
	"com.apple.bsd.dirhelper",
	"com.apple.securityd.xpc",
	"com.apple.SecurityServer",
	"com.apple.coreservices.launchservicesd",
}

const trustdService = "com.apple.trustd.agent"

// String renders the profile for sandbox-exec -p. When rules overlap,
// Seatbelt applies the last one that matches, so denials of reads come
// after the rule that allows reading everything.
func (p Profile) String() string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	line("(version 1)")
	if p.Tag != "" {
		line("(deny default (with message %s))", sbString(p.Tag))
	} else {
		line("(deny default)")
	}

	line("(allow process-exec)")
	line("(allow process-fork)")
	line("(allow process-info* (target same-sandbox))")
	line("(allow signal (target same-sandbox))")
	line("(allow mach-priv-task-port (target same-sandbox))")
	line("(allow sysctl-read)")
	line("(allow user-preference-read)")
	line("(allow ipc-posix-shm)")
	line("(allow ipc-posix-sem)")
	line("(allow iokit-get-properties)")
	line("(allow distributed-notification-post)")
	line("(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))")

	mach := baseMach
	if p.Trustd {
		mach = append(mach[:len(mach):len(mach)], trustdService)
	}
	line("(allow mach-lookup")
	for _, m := range mach {
		line("  (global-name %s)", sbString(m))
	}
	line(")")

	line("(allow file-read*)")
	for _, d := range p.NoRead {
		line("(deny file-read* (subpath %s))", sbString(d))
	}

	for _, d := range p.Write {
		line("(allow file-write* (subpath %s))", sbString(d))
	}
	line(`(allow file-write-data file-ioctl (literal "/dev/null"))`)

	// No host names: Seatbelt only knows "localhost" and "*". Everything
	// else goes through the proxy on one of these ports.
	for _, port := range p.Ports {
		line(`(allow network-outbound (remote ip "localhost:%d"))`, port)
	}
	return b.String()
}

// sbString quotes s as a Seatbelt (Scheme) string literal.
func sbString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
