#!/bin/sh
# WSL2 interop containment: a process inside the sandbox must not reach
# Windows. On WSL, a binfmt_misc entry (WSLInterop) matches the PE "MZ"
# magic and hands the file to /init, which asks the Windows side over the
# socket named in $WSL_INTEROP to launch it. A launched Windows process
# runs as the user outside every Linux boundary airbag sets up, so it
# would be a full escape. This test proves every route is closed:
#   - no cmd.exe/powershell.exe/explorer.exe runs (directly, via PATH,
#     via sh -c or env), and a PE copied into the workspace does not run
#     through the MZ binfmt match;
#   - /init invoked directly does not reach Windows;
#   - WSL_INTEROP and WSLENV are unset and PATH has no /mnt/<drive> entry;
#   - a write to /mnt/c fails and the Windows host network is unreachable.
# The strong signal is a Windows-side effect seen from outside (a marker
# file or returned output); any such sign fails hard.
set -eu
AIRBAG=${AIRBAG:-airbag}
fail() { echo "FAIL: $*"; exit 1; }
discard() { "$AIRBAG" discard --yes >/dev/null 2>&1 || true; }

# Prerequisites. Not WSL at all (the Linux and macOS jobs, a dev Mac):
# skip, even under CI, because there is nothing to test here. On WSL the
# interop binfmt entry is the real prerequisite: if it is gone in CI, the
# one job that exists to test interop must not pass by skipping.
grep -qi microsoft /proc/version 2>/dev/null ||
	{ echo "SKIP: not WSL2 (no 'microsoft' in /proc/version)"; exit 0; }
binfmt=/proc/sys/fs/binfmt_misc/WSLInterop
[ -e "$binfmt" ] || binfmt=/proc/sys/fs/binfmt_misc/WSLInterop-late
if [ ! -e "$binfmt" ]; then
	[ "${CI:-}" = true ] && fail "on WSL but no WSLInterop binfmt entry; interop cannot be tested"
	echo "SKIP: no WSLInterop binfmt entry"; exit 0
fi

T=$(mktemp -d "$HOME/.airbag-wsl-interop-e2e.XXXXXX")
MARKERDIR_UNIX=""
# Only ever remove our own dedicated marker directory, never a bare path.
cleanup() {
	rm -rf "$T"
	case "$MARKERDIR_UNIX" in */airbag-wsl-e2e) rm -rf "$MARKERDIR_UNIX" ;; esac
}
trap cleanup EXIT
mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo hi > README.md && git add -A && git commit -qm init

# Absolute paths to Windows binaries: the CI e2e step strips the Windows
# PATH, so interop must be probed by absolute path, not by PATH lookup.
CMD=/mnt/c/Windows/System32/cmd.exe
PS=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe

# Where markers land: a directory on the Windows filesystem, writable
# from outside the sandbox and observable from both sides. Fall back to
# a fixed /mnt/c path if the Windows TEMP cannot be read.
MARKERDIR_WIN=""
if [ -e "$CMD" ] && command -v wslpath >/dev/null 2>&1; then
	wintemp=$("$CMD" /c 'echo %TEMP%' 2>/dev/null | tr -d '\r') || wintemp=""
	if [ -n "$wintemp" ]; then
		base=$(wslpath -u "$wintemp" 2>/dev/null || echo "")
		[ -n "$base" ] && MARKERDIR_UNIX="$base/airbag-wsl-e2e"
	fi
fi
[ -n "$MARKERDIR_UNIX" ] || MARKERDIR_UNIX=/mnt/c/Windows/Temp/airbag-wsl-e2e
mkdir -p "$MARKERDIR_UNIX" 2>/dev/null || true
if command -v wslpath >/dev/null 2>&1; then
	MARKERDIR_WIN=$(wslpath -w "$MARKERDIR_UNIX" 2>/dev/null || echo "")
fi

# Positive control: interop actually works outside the sandbox. If it
# does not (a runner whose WSL has no live Windows side), the escape
# routes are guaranteed safe; run them as a regression guard but record
# that the control could not be established. A real escape is still
# caught, because any Windows-side marker or output fails hard below.
interop_live=0
marker_live=0
if [ -e "$CMD" ]; then
	if out=$("$CMD" /c echo AIRBAG_MARKER_OK 2>/dev/null); then
		case "$out" in *AIRBAG_MARKER_OK*) interop_live=1 ;; esac
	fi
fi
if [ "$interop_live" = 1 ] && [ -n "$MARKERDIR_WIN" ] && [ -d "$MARKERDIR_UNIX" ]; then
	rm -f "$MARKERDIR_UNIX/control" 2>/dev/null || true
	cmd.exe /c copy /y NUL "$MARKERDIR_WIN\\control" >/dev/null 2>&1 || true
	if [ -e "$MARKERDIR_UNIX/control" ]; then
		marker_live=1
		rm -f "$MARKERDIR_UNIX/control"
	fi
fi
if [ "$interop_live" = 1 ]; then
	echo "positive control: interop is live outside the sandbox (cmd.exe reached Windows); marker files observable: $marker_live"
else
	echo "note: interop binfmt present but cmd.exe did not reach Windows outside the sandbox; escape routes tested as a regression guard"
fi

# no_escape LABEL DESC -- CMD...: run CMD in the sandbox. It must leave no
# Windows-side marker named LABEL and return no Windows output. CMD, if it
# reached Windows, creates "$MARKERDIR_WIN\LABEL" (copy NUL makes an empty
# file with no shell redirection to quote).
no_escape() {
	label=$1 desc=$2
	shift 2
	[ "${1:-}" = -- ] && shift
	rm -f "$MARKERDIR_UNIX/$label" 2>/dev/null || true
	set +e
	out=$("$AIRBAG" run -- "$@" 2>&1)
	status=$?
	set -e
	discard
	if [ -e "$MARKERDIR_UNIX/$label" ]; then
		rm -f "$MARKERDIR_UNIX/$label"
		fail "ESCAPE via $desc: a Windows-side marker was created inside the sandbox"
	fi
	case "$out" in
	*AIRBAG_MARKER_OK*) fail "ESCAPE via $desc: Windows returned output inside the sandbox: $out" ;;
	esac
	echo "blocked: $desc (exit $status)"
}

WINMARK=""
[ -n "$MARKERDIR_WIN" ] && WINMARK="$MARKERDIR_WIN\\"

# Every route that could launch a Windows process. copy NUL <path> drops
# the marker; echo AIRBAG_MARKER_OK returns the token. If the binary does
# not run at all (PATH has no /mnt/c, exec is refused), the run just fails
# and no marker appears -- also blocked.
no_escape cmd-direct   "cmd.exe by absolute path"      -- "$CMD" /c copy /y NUL "${WINMARK}cmd-direct"
no_escape cmd-echo     "cmd.exe echo (output channel)" -- "$CMD" /c echo AIRBAG_MARKER_OK
no_escape cmd-path     "cmd.exe via PATH"              -- cmd.exe /c copy /y NUL "${WINMARK}cmd-path"
no_escape cmd-sh       "cmd.exe via sh -c"             -- sh -c "'$CMD' /c copy /y NUL '${WINMARK}cmd-sh'"
no_escape cmd-env      "cmd.exe via env"               -- env "$CMD" /c copy /y NUL "${WINMARK}cmd-env"
no_escape powershell   "powershell.exe by path"        -- "$PS" -Command exit
no_escape explorer     "explorer.exe"                  -- explorer.exe
no_escape wslvar       "wslvar"                        -- wslvar USERPROFILE
no_escape init-direct  "/init invoked directly"        -- /init

# A PE copied into the workspace: this isolates the binfmt "MZ" match from
# the /mnt/c path. The copy happens outside; the run is inside.
if [ -r "$CMD" ]; then
	cp "$CMD" "$T/proj/payload.exe" 2>/dev/null || true
	if [ -f "$T/proj/payload.exe" ]; then
		no_escape pe-copy "a PE copied into the workspace (binfmt MZ match)" \
			-- ./payload.exe /c copy /y NUL "${WINMARK}pe-copy"
	else
		echo "note: could not copy a PE into the workspace; binfmt-match route not exercised"
	fi
else
	echo "note: $CMD not readable; binfmt-match route not exercised"
fi

# wslpath is a native ELF tool (pure path math, no interop); it should
# still work inside the sandbox and must not be the escape. Only assert it
# reaches no Windows side.
no_escape wslpath "wslpath (native tool, control)" -- wslpath -w /tmp

# Environment: the interop handles must be gone inside the sandbox. The
# single quotes are deliberate: the variables expand in the sandbox's
# shell, not this one.
# shellcheck disable=SC2016
env_out=$("$AIRBAG" run -- sh -c 'printf "WSL_INTEROP=[%s]\n" "${WSL_INTEROP:-}"; printf "WSLENV=[%s]\n" "${WSLENV:-}"; printf "PATH=%s\n" "$PATH"') || fail "env probe run failed"
discard
echo "$env_out" | grep -q 'WSL_INTEROP=\[\]' || fail "WSL_INTEROP is set inside the sandbox: $env_out"
echo "$env_out" | grep -q 'WSLENV=\[\]' || fail "WSLENV is set inside the sandbox: $env_out"
sandbox_path=$(echo "$env_out" | sed -n 's/^PATH=//p')
case ":$sandbox_path:" in
*:/mnt/[a-zA-Z]:* | *:/mnt/[a-zA-Z]/*) fail "PATH has a Windows-drive entry inside the sandbox: $sandbox_path" ;;
esac
echo "env inside the sandbox: WSL_INTEROP and WSLENV unset, PATH has no /mnt/<drive> entry"

# A write to /mnt/c must fail (the host is mounted read-only), and nothing
# must appear on the Windows side.
probe=airbag-wsl-e2e-write
rm -f "/mnt/c/$probe" 2>/dev/null || true
set +e
w=$("$AIRBAG" run -- sh -c "echo escaped > /mnt/c/$probe 2>&1; echo rc=\$?")
set -e
discard
if [ -e "/mnt/c/$probe" ]; then
	rm -f "/mnt/c/$probe"
	fail "ESCAPE: a write to /mnt/c from inside the sandbox reached the Windows filesystem"
fi
echo "$w" | grep -q 'rc=0' && fail "a write to /mnt/c reported success inside the sandbox: $w"
echo "blocked: write to /mnt/c ($w)"

# The Windows host network: the default gateway and the resolv.conf
# nameserver are on the Windows side. They must be reachable outside and
# unreachable inside the sandbox, whose only interface is loopback.
gw=$(ip route 2>/dev/null | awk '/^default/{print $3; exit}')
ns=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)
host=${ns:-$gw}
if [ -z "$host" ]; then
	[ "${CI:-}" = true ] && fail "no default gateway or nameserver to test the host network against"
	echo "SKIP: no host network target (no default route, no nameserver)"
else
	reach='import socket,sys
host,port=sys.argv[1],int(sys.argv[2])
try:
    socket.create_connection((host,port),timeout=4).close(); print("reachable")
except (ConnectionRefusedError,ConnectionResetError):
    print("reachable")  # the host answered; the port is just closed
except OSError:
    print("unreachable")'
	outside=$(python3 -c "$reach" "$host" 53 2>/dev/null || echo error)
	if [ "$outside" != reachable ]; then
		[ "${CI:-}" = true ] && fail "control failed: the Windows host network ($host:53) is not reachable outside the sandbox ($outside)"
		echo "SKIP: host network control unreachable outside the sandbox ($outside); cannot test containment"
	else
		inside=$("$AIRBAG" run -- python3 -c "$reach" "$host" 53 2>/dev/null || echo error)
		discard
		[ "$inside" = unreachable ] || fail "ESCAPE: the Windows host network ($host:53) is reachable inside the sandbox ($inside)"
		echo "blocked: Windows host network $host:53 (reachable outside, unreachable inside)"
	fi
fi

echo PASS
