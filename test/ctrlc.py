#!/usr/bin/env python3
"""TTY check: under a real terminal, Ctrl-C reaches the agent (not
airbag), the agent can handle it, and airbag reports its exit code.
Run as a regular user from inside a git repo: python3 test/ctrlc.py"""
import os
import pty
import select
import sys
import time

AIRBAG = os.environ.get("AIRBAG", "airbag")
AGENT = 'trap "echo got-int; exit 3" INT; echo ready; tty >/dev/null && echo has-tty; while :; do sleep 0.1; done'


def read_until(fd, needle, timeout=20):
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if needle in buf:
                return buf
    raise SystemExit(f"FAIL: no {needle!r} in output:\n{buf.decode(errors='replace')}")


pid, fd = pty.fork()
if pid == 0:
    os.execvp(AIRBAG, [AIRBAG, "run", "--", "sh", "-c", AGENT])

out = read_until(fd, b"ready")
out += read_until(fd, b"has-tty")
os.write(fd, b"\x03")  # Ctrl-C from the terminal
out += read_until(fd, b"got-int")
out += read_until(fd, b"ended (exit 3)")
_, status = os.waitpid(pid, 0)
code = os.waitstatus_to_exitcode(status)
if code != 3:
    raise SystemExit(f"FAIL: airbag exit {code}, want 3\n{out.decode(errors='replace')}")
print("PASS")
