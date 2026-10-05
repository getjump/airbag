#!/bin/sh
# Diagnostic benchmark: standalone command, not an E2E performance assertion.
set -eu
AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-runtime-bench.XXXXXX")
trap 'rm -rf "$T"' EXIT
mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
printf '#include <stdio.h>\nint main(void) { puts("ok"); return 0; }\n' > main.c
cat > workload.py <<'PY'
from pathlib import Path
root=Path('generated');root.mkdir(exist_ok=True)
for i in range(200):
    p=root/str(i);p.write_text('data'*1024);assert p.read_text().startswith('data');p.rename(root/(str(i)+'.moved'))
for p in root.iterdir():p.unlink()
root.rmdir()
PY
git add -A && git commit -qm init
python3 - "$AIRBAG" <<'PY'
import os, statistics, subprocess, sys, time
binary=sys.argv[1]
print('mode\tworkload\tmedian_seconds\tratio',flush=True)
baseline={}
for mode,flags in [('baseline',[]),('fuse',['--fs-policy']),('exec',['--exec-policy']),('both',['--fs-policy','--exec-policy'])]:
    for name,argv in [('c-build',['/usr/bin/sh','-c','cc -O2 main.c -o main && ./main']),('files',['python3','workload.py'])]:
        samples=[]
        for _ in range(3):
            start=time.monotonic()
            subprocess.run([binary,'run',*flags,'--',*argv],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            samples.append(time.monotonic()-start)
            subprocess.run([binary,'discard','--yes'],check=True,stdout=subprocess.DEVNULL)
        median=statistics.median(samples)
        if mode=='baseline':baseline[name]=median
        print(f'{mode}\t{name}\t{median:.4f}\t{median/baseline[name]:.2f}',flush=True)
PY
