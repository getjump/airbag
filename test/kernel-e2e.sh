#!/bin/sh
# The seccomp filter and /proc hardening in effect inside a session:
# kernel-surface syscalls are refused, the supervisor and other
# processes are out of reach, no fds leak in, and no core dump is
# written. The calls the agents actually use still work. See
# internal/sandbox/seccomp.go for why each is refused.
set -eu
AIRBAG=${AIRBAG:-airbag}
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "$HOME/.airbag-kernel-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

# Build the syscall probe for the native ABI and, best effort, for the
# i386 compat ABI (a pure-Go cross build, no C toolchain needed).
(cd "$REPO" && CGO_ENABLED=0 go build -o "$T/kernprobe" ./test/kernprobe) || fail "build kernprobe"
CGO_ENABLED=0 GOARCH=386 go build -C "$REPO" -o "$T/kernprobe386" ./test/kernprobe 2>/dev/null || true

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo hi > README.md && git add -A && git commit -qm init

# Expected verdicts inside the sandbox. io_uring is ENOSYS so libraries
# fall back; the rest are EPERM. socketpair is family-checked like
# socket: the kernel answers a family it lacks with EAFNOSUPPORT, never
# EPERM, so EPERM for AF_TIPC shows the filter refused it, and AF_UNIX
# must still work.
expect() {
	out=$("$AIRBAG" run -- sh -c "'$T/kernprobe'" 2>/dev/null)
	"$AIRBAG" discard --yes >/dev/null 2>&1 || true
	for pair in "$@"; do
		echo "$out" | grep -qx "$pair" || fail "probe ($1 ...) expected '$pair', got:
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
	"socketpair_tipc=EPERM" \
	"socketpair_unix=OK"

# The same calls through the i386 ABI, if this kernel emulates it.
if [ -x "$T/kernprobe386" ]; then
	out=$("$AIRBAG" run -- sh -c "'$T/kernprobe386' 2>&1" 2>/dev/null || true)
	"$AIRBAG" discard --yes >/dev/null 2>&1 || true
	case "$out" in
	*"exec format error"*|*"cannot execute"*|*"ENOEXEC"*|"")
		echo "note: i386 ABI not runnable on this kernel; skipping the 32-bit check" ;;
	*)
		for pair in "io_uring_setup=ENOSYS" "bpf=EPERM" "add_key=EPERM" \
			"socket_vsock=EPERM" "socket_packet=EPERM" \
			"socketpair_tipc=EPERM" "socketpair_unix=OK"; do
			echo "$out" | grep -qx "$pair" || fail "i386 probe expected '$pair', got:
$out"
		done ;;
	esac
fi

# The supervisor (PID 1) is out of reach: ptrace of it fails, and its
# /proc is not readable. hidepid hides it from the process list.
v=$("$AIRBAG" run -- sh -c "'$T/kernprobe' ptrace_pid1" 2>/dev/null); "$AIRBAG" discard --yes >/dev/null 2>&1 || true
[ "$v" = "OK" ] && fail "ptrace of PID 1 succeeded"
out=$("$AIRBAG" run -- sh -c 'cat /proc/1/environ >/dev/null 2>&1 && echo ENVREAD; cat /proc/1/mem >/dev/null 2>&1 && echo MEMREAD; ls /proc/1 >/dev/null 2>&1 && echo P1VISIBLE; true' 2>/dev/null)
"$AIRBAG" discard --yes >/dev/null 2>&1 || true
echo "$out" | grep -q ENVREAD && fail "/proc/1/environ was readable"
echo "$out" | grep -q MEMREAD && fail "/proc/1/mem was readable"
echo "$out" | grep -q P1VISIBLE && fail "PID 1 is visible to the agent (hidepid not set)"

# No caller fd leaks in: only stdio, plus the fd the lister opens on
# /proc/self/fd. Nothing points at an inherited socket.
out=$("$AIRBAG" run -- sh -c 'ls -l /proc/self/fd' 2>/dev/null)
"$AIRBAG" discard --yes >/dev/null 2>&1 || true
echo "$out" | grep -q "socket:" && fail "an inherited socket fd leaked into the agent:
$out"
for fd in 4 5 6 7 8 9; do
	echo "$out" | grep -qE " $fd ->" && fail "an unexpected fd $fd is open in the agent:
$out"
done

# No core dump: the hard and soft limit are 0.
out=$("$AIRBAG" run -- sh -c 'ulimit -c' 2>/dev/null)
"$AIRBAG" discard --yes >/dev/null 2>&1 || true
echo "$out" | grep -qx 0 || fail "RLIMIT_CORE is not 0: $out"

# The tools the agents run still work under the filter.
out=$("$AIRBAG" run -- sh -c 'git --version >/dev/null 2>&1 && echo git-ok; true' 2>/dev/null)
"$AIRBAG" discard --yes >/dev/null 2>&1 || true
echo "$out" | grep -q git-ok || fail "git broke under the filter: $out"

if command -v node >/dev/null; then
	out=$("$AIRBAG" run -- sh -c 'node -e "const n=require(\"os\").cpus().length; require(\"net\"); console.log(\"node-ok\", n>0)" 2>&1' 2>/dev/null)
	"$AIRBAG" discard --yes >/dev/null 2>&1 || true
	echo "$out" | grep -q "node-ok true" || fail "node broke under the filter: $out"
fi

out=$("$AIRBAG" run -- sh -c 'cd "$HOME" && mkdir -p gob && cd gob && (go mod init ex >/dev/null 2>&1 || true) && printf "package main\nfunc main(){}\n" > m.go && GOTOOLCHAIN=local GOFLAGS=-mod=mod go build -o /dev/null . >/dev/null 2>&1 && echo go-ok; true' 2>/dev/null)
"$AIRBAG" discard --yes >/dev/null 2>&1 || true
echo "$out" | grep -q go-ok || fail "go build broke under the filter: $out"

echo PASS
