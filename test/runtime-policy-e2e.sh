#!/bin/sh
# Runtime policy must see opaque Python/make calls and writes to overlay upper.
set -eu
AIRBAG=${AIRBAG:-airbag}
[ -w /dev/fuse ] || { [ "${CI:-}" != true ] || exit 1; echo 'SKIP: /dev/fuse unavailable'; exit 0; }
T=$(mktemp -d "$HOME/.airbag-runtime-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
printf 'keep\n' > protected
printf 'keep-home\n' > "$T/home-protected"
printf 'TOKEN=runtime-secret\n' > .env
echo .env > .gitignore
cat > airbag.yaml <<'YAML'
rules:
  - name: protected-files
    when: effect.source == "fuse" && effect.target.endsWith("protected") && effect.kind in ["fs.write", "fs.delete"]
    verdict: deny
  - name: unreadable
    when: effect.source == "fuse" && effect.target.endsWith("unreadable") && effect.kind == "fs.read"
    verdict: deny
  - name: no-process-marker
    when: effect.source == "seccomp" && effect.kind == "proc.exec" && command.argv.exists(a, a.contains("blocked-process"))
    verdict: deny
  - name: upper-on-resume
    when: effect.source == "fuse" && effect.target.endsWith("upper") && effect.kind == "fs.delete"
    verdict: deny
YAML
printf 'private\n' > unreadable
cat > runtime.py <<'PY'
import os, pathlib, subprocess, sqlite3, mmap, fcntl, socket, ctypes
p = pathlib.Path
for call in [lambda: p('protected').write_text('bad'), lambda: p('protected').unlink(),
             lambda: p('protected').rename('gone'), lambda: p('unreadable').read_text(),
             lambda: p(os.environ['RUNTIME_HOME_PROTECTED']).write_text('bad'),
             lambda: p('replacement').rename('protected')]:
    try:
        call()
    except PermissionError:
        pass
    else:
        raise AssertionError('file policy bypass')
p('upper').write_text('created')
p('upper').write_text('rewritten')
p('renamed').write_text('rename-source'); p('renamed').rename('allowed')
os.link('allowed', 'hardlink'); assert p('hardlink').read_text() == 'rename-source'
p('link').symlink_to('allowed'); assert p('link').read_text() == 'rename-source'
os.chmod('allowed', 0o755)
with open('allowed', 'r+b') as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    m = mmap.mmap(f.fileno(), 0); m[0:1] = b'R'; m.flush(); m.close()
con = sqlite3.connect('test.db'); con.execute('create table example (n integer)'); con.commit(); con.close()
s = socket.socket(socket.AF_UNIX); s.bind('local.sock'); s.close(); p('local.sock').unlink()
# Paths/argv come from the real child syscall, with no shell model involved.
try:
    subprocess.run(['/usr/bin/touch', 'blocked-process'], check=True)
except (PermissionError, subprocess.CalledProcessError):
    pass
else:
    raise AssertionError('execve policy bypass')
# fexecve-style execveat with an already-open executable descriptor.
pid = os.fork()
if pid == 0:
    fd = os.open('/usr/bin/touch', os.O_RDONLY)
    argv = (ctypes.c_char_p * 3)(b'touch', b'blocked-process-at', None)
    env = (ctypes.c_char_p * 1)(None)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.execveat(fd, b'', argv, env, 0x1000)
    os._exit(0 if ctypes.get_errno() == 13 else 1)
assert os.waitpid(pid, 0)[1] == 0
# Init's channel/backing fds must stay inaccessible to the agent. With
# hidepid=2 PID 1 is not visible at all. Without it, listing fd numbers alone
# is permitted on some namespace/proc combinations; the security boundary is
# dereferencing/reopening the supervisor's fd links.
try:
    numbers = os.listdir('/proc/1/fd')
except (FileNotFoundError, PermissionError):
    numbers = []
for number in numbers:
    try:
        os.readlink('/proc/1/fd/' + number)
    except PermissionError:
        pass
    else:
        raise AssertionError('supervisor descriptor link readable')
    try:
        fd = os.open('/proc/1/fd/' + number, os.O_RDONLY | os.O_NONBLOCK)
    except PermissionError:
        pass
    else:
        os.close(fd)
        raise AssertionError('supervisor descriptor reopened')
# Taint must retain the actual reader, even through the outer filesystem.
assert 'runtime-secret' in p('.env').read_text()
PY
printf 'replacement\n' > replacement
printf 'check:\n\tpython3 runtime.py\n' > Makefile
git add -A && git commit -qm init
out=$(RUNTIME_HOME_PROTECTED="$T/home-protected" "$AIRBAG" run --fs-policy --exec-policy -- make check 2>&1) || fail "$out"
echo "$out"
[ "$(cat protected)" = keep ] || fail 'host workspace changed'
[ "$(cat "$T/home-protected")" = keep-home ] || fail 'host HOME changed'
"$AIRBAG" log --json > "$T/log.json"
python3 - "$T/log.json" <<'PY'
import json, sys
es=json.load(open(sys.argv[1]))
assert any(e.get('source')=='fuse' and e['kind']=='fs.write' and e['target'].endswith('/upper') for e in es)
assert any(e.get('source')=='fuse' and e['kind']=='secret.read' and 'python' in e.get('reason','') for e in es)
assert any(e.get('source')=='seccomp' and e.get('detail')=='execveat' and e['verdict']=='deny' for e in es)
assert any(e.get('source')=='seccomp' and e['verdict']=='deny' and 'blocked-process' in e.get('argv',[]) for e in es)
assert all(e.get('pid',0)>0 for e in es if e.get('source'))
PY
# Flags persist across resume; upper-only deletion must still be gated.
out=$("$AIRBAG" run --session last -- python3 -c 'from pathlib import Path
try: Path("upper").unlink()
except PermissionError: pass
else: raise AssertionError("upper deletion bypass")
assert Path("upper").read_text()=="rewritten"' 2>&1) || fail "$out"
"$AIRBAG" review --json > "$T/review.json"
python3 - "$T/review.json" <<'PY'
import json, sys
r=json.load(open(sys.argv[1])); assert r['runtime']['seccomp:proc.exec']>0
assert any(e.get('source')=='fuse' and e['kind']=='fs.delete' for e in r['blocked'])
PY
"$AIRBAG" discard --yes >/dev/null
# Enabling required file policy must not silently fall back when FUSE is off.
if AIRBAG_NO_FUSE=1 "$AIRBAG" run --fs-policy -- /usr/bin/touch bypass > "$T/no-fuse" 2>&1; then fail 'file policy silently disabled'; fi
"$AIRBAG" discard --yes >/dev/null
echo PASS
