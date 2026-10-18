#!/bin/sh
# WSL2 interop containment: a process inside the sandbox must not reach
# Windows. On WSL, a binfmt_misc entry (WSLInterop) matches the PE "MZ"
# magic and hands the file to /init, which asks the Windows side over the
# socket named in $WSL_INTEROP (under /run/WSL) to launch it. A Windows
# process runs as the user outside every Linux boundary airbag sets up.
# The sandbox's private /run is what keeps that socket out of reach; the
# environment scrub (no WSL_INTEROP, WSLENV or /mnt/<drive> in PATH) is a
# second layer. This test checks both, each against a control outside:
#   - no Windows program runs from inside by any route: cmd.exe by path,
#     via PATH, sh -c and env, with WSL_INTEROP set by the agent itself,
#     powershell.exe, explorer.exe, wslvar, /init, and a PE copied into
#     the workspace (the binfmt match, off /mnt/c);
#   - WSL_INTEROP and WSLENV are unset and PATH has no /mnt/<drive> entry;
#   - /mnt/c is read-only and the Windows host network is unreachable.
# A Windows-side effect seen from outside (a marker directory, or output
# only Windows prints) fails the test.
set -eu
AIRBAG=${AIRBAG:-airbag}
fail() { echo "FAIL: $*"; exit 1; }
discard() { "$AIRBAG" discard --yes >/dev/null 2>&1 || true; }
# need MSG: a prerequisite is missing. Under CI that fails, so the one job
# that exists to run this cannot pass by skipping it.
need() {
	[ "${CI:-}" = true ] && fail "$1"
	echo "SKIP: $1"
	exit 0
}

# Not WSL at all (the Linux and macOS jobs, a developer's machine):
# nothing to test, so skip even under CI.
grep -qi microsoft /proc/version 2>/dev/null ||
	{ echo "SKIP: not WSL2 (no 'microsoft' in /proc/version)"; exit 0; }
[ -e /proc/sys/fs/binfmt_misc/WSLInterop ] || [ -e /proc/sys/fs/binfmt_misc/WSLInterop-late ] ||
	need "on WSL but no WSLInterop binfmt entry"

CMD=/mnt/c/Windows/System32/cmd.exe
PS=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
[ -e "$CMD" ] || need "$CMD is missing"

# Positive control 1: interop works outside, so a block inside means
# something. Absolute path: the CI step strips the Windows PATH.
case "$("$CMD" /c echo AIRBAG_MARKER_OK 2>/dev/null)" in
*AIRBAG_MARKER_OK*) ;;
*) need "cmd.exe does not reach Windows outside the sandbox (interop not live)" ;;
esac

# Markers: directories Windows creates (cmd's mkdir needs no shell
# redirection to quote) under C:\Users\Public. Windows makes them, not
# Linux: /mnt/c is mounted uid=0, so this user may not write it from Linux.
[ -d /mnt/c/Users/Public ] || need "no /mnt/c/Users/Public for markers"
MARK_UNIX=/mnt/c/Users/Public/airbag-wsl-e2e.$$
MARK_WIN="C:\\Users\\Public\\airbag-wsl-e2e.$$"
T=$(mktemp -d "$HOME/.airbag-wsl-interop-e2e.XXXXXX")
trap 'rm -rf "$T"; "$CMD" /c rmdir /s /q "$MARK_WIN" >/dev/null 2>&1 || true' EXIT

# Positive control 2: a Windows process launched from outside leaves a
# marker this script sees, so "no marker" inside is a real observation.
out=$("$CMD" /c mkdir "$MARK_WIN" 2>&1) || true
[ -d "$MARK_UNIX" ] || fail "control: cmd.exe outside did not create $MARK_WIN (seen as $MARK_UNIX): $out"
echo "controls: interop is live outside the sandbox, and its markers are visible"

# The interop handles a session would otherwise inherit: the caller's
# WSL_INTEROP (or a live socket), a WSLENV, and the Windows PATH entries.
# Set here, so the scrub is tested whatever the caller's environment is.
SOCK=${WSL_INTEROP:-}
if [ -z "$SOCK" ] || [ ! -S "$SOCK" ]; then
	SOCK=$(find /run/WSL -maxdepth 1 -name '*_interop' -type s 2>/dev/null | head -n 1)
fi
[ -S "$SOCK" ] || need "no interop socket under /run/WSL"
run() {
	PATH="$PATH:/mnt/c/Windows/System32:/mnt/c/Windows" WSL_INTEROP="$SOCK" WSLENV=AIRBAG_E2E/u \
		"$AIRBAG" run -- "$@"
}

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo hi > README.md && git add -A && git commit -qm init
cp "$CMD" payload.exe || fail "cannot copy $CMD into the workspace"

# no_escape LABEL DESC CMD...: CMD runs in the sandbox and, had it reached
# Windows, would leave the marker LABEL or print AIRBAG_MARKER_OK.
no_escape() {
	label=$1 desc=$2
	shift 2
	set +e
	out=$(run "$@" 2>&1)
	status=$?
	set -e
	discard
	[ -e "$MARK_UNIX/$label" ] && fail "ESCAPE via $desc: Windows created $MARK_WIN\\$label"
	case "$out" in *AIRBAG_MARKER_OK*) fail "ESCAPE via $desc: Windows output reached the sandbox: $out" ;; esac
	[ "$status" = 0 ] && fail "$desc succeeded inside the sandbox: $out"
	echo "blocked: $desc (exit $status)"
}
m() { printf '%s\\%s' "$MARK_WIN" "$1"; }

no_escape direct "cmd.exe by absolute path" "$CMD" /c mkdir "$(m direct)"
no_escape echo "cmd.exe output" "$CMD" /c echo AIRBAG_MARKER_OK
no_escape path "cmd.exe via PATH" cmd.exe /c mkdir "$(m path)"
# shellcheck disable=SC2016 # $0 and $1 expand in the sandbox's sh
no_escape sh "cmd.exe via sh -c" sh -c '"$0" /c mkdir "$1"' "$CMD" "$(m sh)"
no_escape env "cmd.exe via env" env "$CMD" /c mkdir "$(m env)"
# The agent can name the host's socket itself: the scrub is not the
# boundary, the socket's absence from the sandbox's /run is.
no_escape own-sock "cmd.exe with WSL_INTEROP set inside" env WSL_INTEROP="$SOCK" "$CMD" /c mkdir "$(m own-sock)"
no_escape run-wsl "cmd.exe with WSL_INTEROP=/run/WSL/1_interop" env WSL_INTEROP=/run/WSL/1_interop "$CMD" /c mkdir "$(m run-wsl)"
no_escape pe "a PE copied into the workspace" ./payload.exe /c mkdir "$(m pe)"
no_escape ps "powershell.exe" "$PS" -NoProfile -Command "New-Item -ItemType Directory '$(m ps)'"
no_escape explorer "explorer.exe" explorer.exe "$(m explorer)"
no_escape wslvar "wslvar" wslvar USERPROFILE
no_escape init "/init invoked directly" /init "$CMD" /c mkdir "$(m init)"

# The scrub itself. The single quotes are deliberate: the variables expand
# in the sandbox's shell.
# shellcheck disable=SC2016
env_out=$(run sh -c 'printf "WSL_INTEROP=[%s]\nWSLENV=[%s]\nPATH=%s\n" "${WSL_INTEROP:-}" "${WSLENV:-}" "$PATH"' 2>&1) ||
	fail "env probe failed: $env_out"
discard
echo "$env_out" | grep -qx 'WSL_INTEROP=\[\]' || fail "WSL_INTEROP reached the agent: $env_out"
echo "$env_out" | grep -qx 'WSLENV=\[\]' || fail "WSLENV reached the agent: $env_out"
case ":$(echo "$env_out" | sed -n 's/^PATH=//p'):" in
*:/mnt/[a-zA-Z]:* | *:/mnt/[a-zA-Z]/*) fail "a /mnt/<drive> PATH entry reached the agent: $env_out" ;;
esac
echo "scrubbed: WSL_INTEROP, WSLENV and the /mnt/<drive> PATH entries do not reach the agent"

# /mnt/c is read-only inside. The kernel checks a read-only mount before
# permissions, so inside the error must be EROFS whatever this user's
# rights on drvfs are; outside it must be something else (success, or a
# permission error), or the read-only mount is not the sandbox's.
set +e
o=$( (printf x > "$MARK_UNIX/outside") 2>&1)
ostatus=$?
set -e
case "$o" in *"Read-only file system"*) fail "control: /mnt/c is read-only outside the sandbox too: $o" ;; esac
if [ "$ostatus" = 0 ]; then rm -f "$MARK_UNIX/outside"; o=ok; fi
set +e
w=$(run sh -c 'printf x > "$1/inside"' sh "$MARK_UNIX" 2>&1)
status=$?
set -e
discard
[ -e "$MARK_UNIX/inside" ] && fail "ESCAPE: a write to /mnt/c from inside reached Windows"
[ "$status" != 0 ] || fail "a write to /mnt/c succeeded inside the sandbox"
case "$w" in *"Read-only file system"*) ;; *) fail "a write to /mnt/c failed inside for another reason than a read-only mount: $w" ;; esac
echo "blocked: write to /mnt/c (outside: $o; inside: read-only file system)"

# The Windows host network: the resolv.conf nameserver or the default
# gateway, reachable outside and not inside, where only loopback exists.
host=$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf 2>/dev/null)
[ -n "$host" ] || host=$(ip route 2>/dev/null | awk '/^default/ { print $3; exit }')
[ -n "$host" ] || need "no nameserver or default gateway to test the host network"
reach='import socket, sys
try:
    socket.create_connection((sys.argv[1], 53), timeout=4).close()
    print("reachable")
except (ConnectionRefusedError, ConnectionResetError):
    print("reachable")  # the host answered; the port is closed
except OSError:
    print("unreachable")'
outside=$(python3 -c "$reach" "$host" 2>&1)
[ "$outside" = reachable ] || need "control: $host:53 is not reachable outside the sandbox ($outside)"
# stdout only: airbag's own session lines go to stderr.
inside=$(run python3 -c "$reach" "$host" 2>/dev/null)
discard
[ "$inside" = unreachable ] || fail "ESCAPE: the Windows host network ($host:53) is reachable inside: $inside"
echo "blocked: Windows host network $host:53 (reachable outside, not inside)"
echo PASS
