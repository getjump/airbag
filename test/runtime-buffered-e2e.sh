#!/bin/sh
# Buffered decisions keep policy/taint synchronous and drain before clean stop.
set -eu
AIRBAG=${AIRBAG:-airbag}
[ -w /dev/fuse ] || { [ "${CI:-}" != true ] || exit 1; echo 'SKIP: /dev/fuse unavailable'; exit 0; }
T=$(mktemp -d "$HOME/.airbag-buffered-e2e.XXXXXX")
AIRBAG_HOME=$(mktemp -d /var/tmp/airbag-buffered-e2e.XXXXXX)
export AIRBAG_HOME
trap 'rm -rf "$T" "$AIRBAG_HOME"' EXIT
mkdir "$T/project"
cd "$T/project"
git init -q -b main
git config user.email e2e@example.com
git config user.name e2e
printf 'TOKEN=buffered-secret\n' > .env
printf 'keep\n' > protected
echo .env > .gitignore
cat > airbag.yaml <<'YAML'
rules:
  - name: protected
    when: effect.source == "fuse" && effect.target.endsWith("/protected") && effect.kind in ["fs.write", "fs.delete"]
    verdict: deny
  - name: tainted-file
    when: session.tainted && effect.source == "fuse" && effect.target.endsWith("/tainted-blocked") && effect.kind == "fs.write"
    verdict: deny
YAML
cat > buffered.py <<'PY'
from pathlib import Path
for i in range(200):
    Path('created-'+str(i)).write_text('value')
try: Path('protected').write_text('bad')
except PermissionError: pass
else: raise AssertionError('buffered mode bypassed policy')
assert 'buffered-secret' in Path('.env').read_text()
try: Path('tainted-blocked').write_text('bad')
except PermissionError: pass
else: raise AssertionError('secret taint did not affect policy')
Path('last-event').write_text('flush-on-stop')
PY
git add -A
git commit -qm init
"$AIRBAG" run --fs-policy --exec-policy --runtime-audit=buffered --runtime-profile --fs-cache=sealed -- python3 buffered.py
"$AIRBAG" log --json > "$T/events.json"
python3 - "$T/events.json" "$AIRBAG_HOME" <<'PY'
import json, pathlib, sys
events=json.load(open(sys.argv[1]))
for i in range(200):
    assert any(e.get('source')=='fuse' and e['kind']=='fs.write' and e['target'].endswith('/created-'+str(i)) for e in events)
assert any(e['kind']=='fs.write' and e['target'].endswith('/last-event') for e in events)
assert any(e['kind']=='secret.read' and e.get('source')=='fuse' for e in events)
assert any(e['kind']=='fs.write' and e['target'].endswith('/tainted-blocked') and e['verdict']=='deny' for e in events)
session=next(pathlib.Path(sys.argv[2]).glob('s-*'))
meta=json.load(open(session/'meta.json'))
assert meta['runtime_audit']=='buffered' and meta['file_cache']=='sealed'
profile=json.load(open(session/'runtime-profile-1.json'))
assert profile['buffered']['events']>200 and profile['buffered']['commits']>0
assert profile['buffered']['failures']==0
assert profile['runtime']['metrics']['runtime.audit.durable']['count']>0  # secret barrier
assert profile['runtime']['metrics']['child.cache.unsealed']['count']>0
PY
# The taint barrier is durable even though ordinary decisions were buffered.
"$AIRBAG" run --session last -- python3 -c 'from pathlib import Path
try: Path("tainted-blocked").write_text("bad")
except PermissionError: pass
else: raise AssertionError("resume lost secret taint")'
"$AIRBAG" run --session last --runtime-audit=durable -- python3 -c 'from pathlib import Path; Path("durable-again").write_text("ok")'
python3 - "$AIRBAG_HOME" <<'PY'
import json,pathlib,sys
session=next(pathlib.Path(sys.argv[1]).glob('s-*'))
assert json.load(open(session/'meta.json'))['runtime_audit']=='durable'
assert json.load(open(session/'runtime-profile-3.json'))['audit_mode']=='durable'
PY
[ "$(cat protected)" = keep ]
[ ! -e last-event ]
"$AIRBAG" discard --yes >/dev/null
echo PASS
