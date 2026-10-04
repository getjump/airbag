#!/usr/bin/env python3
"""Run a command in a pty and type answers at its prompts, so a
recording shows the keystrokes: drive.py 'RULES' -- CMD...

RULES is JSON: {"pattern": ["answer", ...], "": [default answers]}.
At each apply prompt the unit's title picks the rule; answers are used
in turn, the last one repeats. A [y/N] question is answered with "y"."""
import json, os, pty, re, select, sys, time

rules = json.loads(sys.argv[1])
cmd = sys.argv[sys.argv.index("--") + 1:]
used = {}
pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)

def answer(key):
    seq = rules.get(key, rules.get("", ["y"]))
    n = used.get(key, 0)
    used[key] = n + 1
    return seq[min(n, len(seq) - 1)]

def typ(s):
    time.sleep(1.0)
    for ch in s:
        os.write(fd, ch.encode())
        time.sleep(0.12)
    os.write(fd, b"\r")

buf = ""
while True:
    r, _, _ = select.select([fd], [], [], 0.2)
    if not r:
        continue
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    sys.stdout.buffer.write(data)
    sys.stdout.flush()
    buf = (buf + data.decode(errors="replace"))[-4000:]
    if buf.endswith("[q]uit: "):
        title = re.findall(r"\[\d+/\d+\] ([^\r\n]*)", buf)[-1]
        key = next((k for k in rules if k and k in title), "")
        buf = ""
        typ(answer(key))
    elif buf.endswith("[y/N] "):
        buf = ""
        typ("y")
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
