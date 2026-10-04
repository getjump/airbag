// Package seatbelt writes the macOS sandbox profile airbag runs the
// agent under (sandbox-exec -p). It is plain text generation, so it
// builds and is tested on any platform; only darwin runs it.
//
// The profile is deny-first: reading is allowed except under NoRead,
// writing only under Write, outbound traffic only to the localhost ports
// in Ports and the unix sockets in Sockets. Seatbelt cannot filter by
// host name, so the network goes through airbag's proxy on one of those
// ports, as in Claude Code's sandbox-runtime. When rules overlap the
// last matching one wins, so every denial follows the allowance it
// narrows.
//
// Paths must be real paths (/private/var/..., not /var/...): Seatbelt
// matches the resolved path of a file.
package seatbelt

import (
	"fmt"
	"strings"
)

type Profile struct {
	// Tag is added to every denial, so the violation log can be
	// filtered for this session.
	Tag string
	// Write: directories the agent may write (the workspace branch, the
	// session's temp and cache directories, agent state).
	Write []string
	// WriteFiles: single files the agent may write.
	WriteFiles []string
	// NoRead: directories and files the agent may not read (credentials).
	NoRead []string
	// NoWrite: paths under Write that stay read-only.
	NoWrite []string
	// Ports: localhost TCP ports the agent may connect to.
	Ports []int
	// Sockets: unix sockets the agent may connect to (airbag's control
	// socket).
	Sockets []string
	// Trustd allows com.apple.trustd.agent, which Go programs need to
	// verify TLS certificates with the platform verifier: always when
	// their go.mod declares a Go version before 1.27 (whatever Go builds
	// them), and with a later go line when SSL_CERT_FILE and SSL_CERT_DIR
	// are unset. It widens what the agent can reach.
	Trustd bool
}

// mach services a shell, git, Node and Go programs need, after
// sandbox-runtime's profile.
var baseMach = []string{
	"com.apple.audio.systemsoundserver",
	"com.apple.bsd.dirhelper",
	"com.apple.coreservices.launchservicesd",
	"com.apple.distributed_notifications@Uv3",
	"com.apple.FontObjectsServer",
	"com.apple.fonts",
	"com.apple.logd",
	"com.apple.lsd.mapdb",
	"com.apple.PowerManagement.control",
	"com.apple.SecurityServer",
	"com.apple.securityd.xpc",
	"com.apple.system.logger",
	"com.apple.system.notification_center",
	"com.apple.system.opendirectoryd.libinfo",
	"com.apple.system.opendirectoryd.membership",
}

const TrustdService = "com.apple.trustd.agent"

// String renders the profile for sandbox-exec -p.
func (p Profile) String() string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	line("(version 1)")
	if p.Tag != "" {
		line("(deny default (with message %s))", Quote(p.Tag))
	} else {
		line("(deny default)")
	}
	for _, r := range []string{
		"(allow process-exec)",
		"(allow process-fork)",
		"(allow process-info* (target same-sandbox))",
		"(allow signal (target same-sandbox))",
		"(allow mach-priv-task-port (target same-sandbox))",
		"(allow sysctl-read)",
		"(allow user-preference-read)",
		"(allow ipc-posix-shm)",
		"(allow ipc-posix-sem)",
		"(allow iokit-get-properties)",
		"(allow distributed-notification-post)",
		"(allow pseudo-tty)",
		"(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))",
	} {
		line("%s", r)
	}

	mach := append([]string(nil), baseMach...)
	if p.Trustd {
		mach = append(mach, TrustdService)
	}
	line("(allow mach-lookup")
	for _, m := range mach {
		line("  (global-name %s)", Quote(m))
	}
	line(")")

	line("(allow file-read*)")
	for _, d := range p.NoRead {
		line("(deny file-read* (subpath %s))", Quote(d))
	}

	for _, d := range p.Write {
		line("(allow file-write* (subpath %s))", Quote(d))
	}
	for _, f := range p.WriteFiles {
		line("(allow file-write* (literal %s))", Quote(f))
	}
	line(`(allow file-write-data file-ioctl (literal "/dev/null") (literal "/dev/zero") (literal "/dev/tty") (regex #"^/dev/ttys[0-9]+$"))`)
	for _, d := range p.NoWrite {
		line("(deny file-write* (subpath %s))", Quote(d))
	}

	for _, port := range p.Ports {
		line(`(allow network-outbound (remote ip "localhost:%d"))`, port)
	}
	for _, s := range p.Sockets {
		line("(allow network-outbound (remote unix-socket (path-literal %s)))", Quote(s))
	}
	return b.String()
}

// Quote writes s as a Seatbelt (Scheme) string literal.
func Quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
