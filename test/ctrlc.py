#!/usr/bin/env python3
"""TTY check under a real terminal:
- the agent gets a pseudo-terminal of its own, not the user's;
- TIOCSTI is refused inside;
- a resize reaches the agent;
- Ctrl-Z stops the agent and it continues (no job control here, so
  airbag does not stop itself);
- Ctrl-C reaches the agent (not airbag), and airbag reports its exit code.
Run as a regular user from inside a git repo: python3 test/ctrlc.py"""
import fcntl
import os
import pty
import select
import struct
import termios
import time

AIRBAG = os.environ.get("AIRBAG", "airbag")
AGENT = r"""
trap "echo got-int; exit 3" INT
trap 'echo "winch $(stty size)"' WINCH
echo "tty=$(tty)"
python3 -c '
import fcntl, termios
try:
    fcntl.ioctl(0, termios.TIOCSTI, b"x")
    print("sti=allowed")
except OSError as e:
    print("sti=errno-%d" % e.errno)
'
echo ready
while :; do sleep 0.1; done
"""


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


def fail(msg, out):
    raise SystemExit(f"FAIL: {msg}\n{out.decode(errors='replace')}")


pid, fd = pty.fork()
if pid == 0:
    os.execvp(AIRBAG, [AIRBAG, "run", "--", "sh", "-c", AGENT])

outer = os.readlink(f"/proc/{pid}/fd/0")
out = read_until(fd, b"ready")
line = next(l for l in out.splitlines() if l.startswith(b"tty="))
inner = line[4:].decode().strip()
if not inner.startswith("/dev/pts/") or inner == outer:
    fail(f"agent's terminal is {inner!r}, the user's is {outer!r}", out)
if b"sti=errno-1" not in out:
    fail("TIOCSTI was not refused with EPERM", out)

# Resize the user's terminal: airbag passes the size on.
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
out += read_until(fd, b"winch 40 100")

# Ctrl-Z stops the agent; without job control airbag continues it.
os.write(fd, b"\x1a")
time.sleep(1)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 41, 101, 0, 0))
out += read_until(fd, b"winch 41 101")

os.write(fd, b"\x03")  # Ctrl-C from the terminal
out += read_until(fd, b"got-int")
out += read_until(fd, b"ended (exit 3)")
_, status = os.waitpid(pid, 0)
code = os.waitstatus_to_exitcode(status)
if code != 3:
    fail(f"airbag exit {code}, want 3", out)
print("PASS")
