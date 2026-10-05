#!/bin/sh
# The seccomp filter and /proc hardening in effect inside a session:
# kernel-surface syscalls are refused, the supervisor and other
# processes are out of reach, no fds leak in, and core dumps are capped
# at 1 byte. The calls the agents actually use still work. See
# internal/sandbox/seccomp.go for why each is refused.
set -eu
AIRBAG=${AIRBAG:-airbag}
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "$HOME/.airbag-kernel-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
discard() { "$AIRBAG" discard --yes >/dev/null 2>&1 || true; }

# Build the syscall probe for the native ABI and, best effort, for the
# i386 compat ABI (a pure-Go cross build, no C toolchain needed).
(cd "$REPO" && CGO_ENABLED=0 go build -o "$T/kernprobe" ./test/kernprobe) || fail "build kernprobe"
CGO_ENABLED=0 GOARCH=386 go build -C "$REPO" -o "$T/kernprobe386" ./test/kernprobe 2>/dev/null || true

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo hi > README.md && git add -A && git commit -qm init

# The probes whose refusal is only meaningful if the kernel does not
# already refuse them must pass outside the filter. socket(AF_ALG) and
# netlink NETFILTER are answered with success or EAFNOSUPPORT, never
# EPERM, by a bare kernel; AF_PACKET would need CAP_NET_RAW, so it is not
# used for this check.
base=$("$T/kernprobe" 2>/dev/null || true)
for p in socket_alg netlink_netfilter netlink_route; do
	v=$(echo "$base" | sed -n "s/^$p=//p")
	[ "$v" = EPERM ] && fail "baseline outside the filter already refuses $p ($v); the inside check would be meaningless"
done

# Expected verdicts inside the sandbox. io_uring is ENOSYS so libraries
# fall back; the family and netlink-protocol refusals are EPERM; the
# allowed netlink protocol and socketpair(AF_UNIX) still work.
expect() {
	out=$("$AIRBAG" run -- sh -c "'$T/kernprobe'" 2>/dev/null)
	discard
	for pair in "$@"; do
		echo "$out" | grep -qx "$pair" || fail "probe expected '$pair', got:
$out"
	done
}
expect \
	"io_uring_setup=ENOSYS" \
	"bpf=EPERM" \
	"perf_event_open=EPERM" \
	"add_key=EPERM" \
	"userfaultfd=EPERM" \
	"socket_vsock=EPERM" \
	"socket_packet=EPERM" \
	"socket_alg=EPERM" \
	"socketpair_tipc=EPERM" \
	"socketpair_unix=OK" \
	"netlink_netfilter=EPERM" \
	"netlink_route=OK"

# The same calls through the i386 ABI, if this kernel emulates it.
if [ -x "$T/kernprobe386" ]; then
	out=$("$AIRBAG" run -- sh -c "'$T/kernprobe386' 2>&1" 2>/dev/null || true)
	discard
	case "$out" in
	*"exec format error"*|*"cannot execute"*|*"ENOEXEC"*|"")
		echo "note: i386 ABI not runnable on this kernel; skipping the 32-bit check" ;;
	*)
		for pair in "io_uring_setup=ENOSYS" "bpf=EPERM" "add_key=EPERM" \
			"socket_vsock=EPERM" "socket_alg=EPERM" \
			"socketpair_tipc=EPERM" "socketpair_unix=OK" \
			"netlink_netfilter=EPERM" "netlink_route=OK"; do
			echo "$out" | grep -qx "$pair" || fail "i386 probe expected '$pair', got:
$out"
		done ;;
	esac
fi

# --strict refuses the new mount API with ENOSYS; by default it is
# allowed and the kernel answers (not ENOSYS).
d=$("$AIRBAG" run -- sh -c "'$T/kernprobe' fsopen" 2>/dev/null); discard
[ "$d" = ENOSYS ] && fail "fsopen was ENOSYS without --strict: $d"
v=$("$AIRBAG" run --strict -- sh -c "'$T/kernprobe' fsopen" 2>/dev/null); discard
[ "$v" = ENOSYS ] || fail "fsopen under --strict expected ENOSYS, got $v"

# --strict also refuses i386 socketcall socket creation (the family is
# behind a pointer the filter cannot read); by default it works.
if [ -x "$T/kernprobe386" ]; then
	sc=$("$AIRBAG" run -- sh -c "'$T/kernprobe386' socketcall_socket 2>&1" 2>/dev/null || true); discard
	case "$sc" in
	OK)
		sv=$("$AIRBAG" run --strict -- sh -c "'$T/kernprobe386' socketcall_socket" 2>/dev/null); discard
		[ "$sv" = EPERM ] || fail "i386 socketcall under --strict expected EPERM, got $sv" ;;
	*) : ;; # i386 not runnable, or socketcall unavailable; already noted above
	esac
fi

# The supervisor (PID 1) is out of reach: ptrace of it fails, and its
# /proc is not readable. hidepid hides it from the process list.
v=$("$AIRBAG" run -- sh -c "'$T/kernprobe' ptrace_pid1" 2>/dev/null); discard
[ "$v" = "OK" ] && fail "ptrace of PID 1 succeeded"
out=$("$AIRBAG" run -- sh -c 'cat /proc/1/environ >/dev/null 2>&1 && echo ENVREAD; cat /proc/1/mem >/dev/null 2>&1 && echo MEMREAD; ls /proc/1 >/dev/null 2>&1 && echo P1VISIBLE; true' 2>/dev/null)
discard
echo "$out" | grep -q ENVREAD && fail "/proc/1/environ was readable"
echo "$out" | grep -q MEMREAD && fail "/proc/1/mem was readable"
echo "$out" | grep -q P1VISIBLE && fail "PID 1 is visible to the agent (hidepid not set)"

# /dev/kmsg and /dev/userfaultfd are hidden: /dev/null (1:3) is bound
# over each node the host has. The device number is checked, not a read:
# with dmesg_restrict=1 a read of the real /dev/kmsg is empty too.
for dev in /dev/kmsg /dev/userfaultfd; do
	[ -e "$dev" ] || continue
	v=$("$AIRBAG" run -- sh -c "stat -c %t:%T $dev" 2>/dev/null); discard
	[ "$v" = 1:3 ] || fail "$dev is not hidden: device $v, want 1:3 (/dev/null)"
done

# fdsge3 prints the fd number and target for every open fd >= 3, so the
# checks ignore stdio (which may itself be a socket).
fdsge3() { echo "$1" | awk '$9 ~ /^[0-9]+$/ && $9 + 0 >= 3 { print $9, $11 }'; }

# No caller fd leaks in: of the fds >= 3 the agent has, none is an
# inherited socket (the lister's own dir fd is not a socket).
out=$("$AIRBAG" run -- sh -c 'ls -l /proc/self/fd' 2>/dev/null)
discard
fdsge3 "$out" | grep -q "socket:" && fail "an inherited socket fd reached the agent:
$out"

# An fd the caller leaves open (fd 7) must not reach the agent. It is a
# file this script makes, so the open cannot fail and pass the check
# without testing anything.
echo fd7 > "$T/inherited-fd7"
out=$(exec 7<"$T/inherited-fd7"; "$AIRBAG" run -- sh -c 'ls -l /proc/self/fd' 2>/dev/null)
discard
fdsge3 "$out" | grep -q "inherited-fd7" && fail "an inherited fd (7 -> $T/inherited-fd7) reached the agent:
$out"

# Core dumps are capped: RLIMIT_CORE is 1 byte, soft and hard (see
# init.go), which stops file dumps and pipe handlers. ulimit -c reports
# 512-byte blocks, so read the byte value from /proc/self/limits instead.
out=$("$AIRBAG" run -- sh -c 'grep "Max core file size" /proc/self/limits' 2>/dev/null)
discard
echo "$out" | awk '{ exit !($5 == "1" && $6 == "1") }' || fail "RLIMIT_CORE soft/hard not 1 byte: $out"

# --strict skips a change to the limit (at 0 a pipe core_pattern runs
# again): the call reports success and the limit stays 1 byte. By
# default the kernel lets a process lower it. A read, as `ulimit -c`
# makes, works in both. corelimit prints "ok" when the read and the
# change both report success, then the core line of /proc/self/limits.
corelimit='ulimit -c >/dev/null && ulimit -S -c 0 && echo ok; grep "Max core file size" /proc/self/limits'
v=$("$AIRBAG" run -- sh -c "$corelimit" 2>/dev/null); discard
echo "$v" | awk '$1 == "ok" { ok = 1 } /^Max core/ { s = $5 } END { exit !(ok && s == "0") }' ||
	fail "RLIMIT_CORE without --strict: expected a read and the soft limit lowered to 0, got: $v"
v=$("$AIRBAG" run --strict -- sh -c "$corelimit" 2>/dev/null); discard
echo "$v" | awk '$1 == "ok" { ok = 1 } /^Max core/ { s = $5; h = $6 } END { exit !(ok && s == "1" && h == "1") }' ||
	fail "RLIMIT_CORE under --strict: expected a read, a change reported as done, and the limit still 1 byte, got: $v"

# Started with a hard core limit of 0, which an unprivileged airbag
# cannot raise to 1 (and at 0 a pipe core_pattern still runs), --strict
# refuses to run and the default mode warns. Root may raise it, so this
# runs as a regular user only.
if [ "$(id -u)" != 0 ] && command -v prlimit >/dev/null; then
	v=$(prlimit --core=0:0 "$AIRBAG" run --strict -- echo agent-ran 2>&1) || true; discard
	echo "$v" | grep -q agent-ran && fail "--strict ran with a core limit it could not set: $v"
	echo "$v" | grep -q "limit core dumps" || fail "--strict did not say why it stopped: $v"
	v=$(prlimit --core=0:0 "$AIRBAG" run -- echo agent-ran 2>&1); discard
	echo "$v" | grep -q agent-ran || fail "the default mode did not run with a core limit it could not set: $v"
	echo "$v" | grep -q "could not limit core dumps" || fail "no warning for a core limit airbag could not set: $v"
fi

# gpg lowers its own core limit at start and stops if that fails; under
# --strict the skipped change keeps it working.
if command -v gpg >/dev/null; then
	v=$("$AIRBAG" run --strict -- sh -c 'gpg --version >/dev/null && echo gpg-ok; true' 2>/dev/null); discard
	[ "$v" = gpg-ok ] || fail "gpg --version failed under --strict: $v"
fi

# The tools the agents run still work under the filter.
out=$("$AIRBAG" run -- sh -c 'git --version >/dev/null 2>&1 && echo git-ok; true' 2>/dev/null)
discard
echo "$out" | grep -q git-ok || fail "git broke under the filter: $out"

if command -v node >/dev/null; then
	out=$("$AIRBAG" run -- sh -c 'node -e "const n=require(\"os\").cpus().length; require(\"net\"); console.log(\"node-ok\", n>0)" 2>&1' 2>/dev/null)
	discard
	echo "$out" | grep -q "node-ok true" || fail "node broke under the filter: $out"
fi

out=$("$AIRBAG" run -- sh -c 'cd && mkdir -p gob && cd gob && (go mod init ex >/dev/null 2>&1 || true) && printf "package main\nfunc main(){}\n" > m.go && GOTOOLCHAIN=local GOFLAGS=-mod=mod go build -o /dev/null . >/dev/null 2>&1 && echo go-ok; true' 2>/dev/null)
discard
echo "$out" | grep -q go-ok || fail "go build broke under the filter: $out"

echo PASS
