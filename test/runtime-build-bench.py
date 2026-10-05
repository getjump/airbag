#!/usr/bin/env python3
"""Paired build measurements, not a timing assertion. Needs Linux FUSE/userns.

Use --before <previous binary> --after <current binary> --source <fixed snapshot>.
--diagnostic adds separately profiled ablations; paired production runs do not
enable profiling. Diagnostic binaries must be built with -tags=airbag_bench.
Both binaries build the same source, offline, with an empty Go build cache per
trial. Cold means empty GOCACHE, not cold disk/OS/module caches. The baseline is
Airbag without runtime flags, not an unsandboxed host build. Phase wall times
exclude sandbox startup; session wall/CPU and audit counts are recorded too.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import statistics
import subprocess
import tempfile
import time

INNER = r'''
import hashlib, json, os, pathlib, resource, subprocess, time
root=pathlib.Path.cwd()
cache=root/'.bench-cache'
cache.mkdir()
(root/'.bench-bin').mkdir()
env=dict(os.environ, GOCACHE=str(cache), CGO_ENABLED='0', GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local', GOTELEMETRY='off')
argv=['go','build','-p',os.environ['BENCH_PARALLELISM'],'-mod=readonly','-buildvcs=false','-o','.bench-bin/airbag','./cmd/airbag']
original=(root/'cmd/airbag/main.go').read_text()
def build(phase,iteration):
 before=resource.getrusage(resource.RUSAGE_CHILDREN);start=time.monotonic()
 subprocess.run(argv,env=env,check=True)
 elapsed=time.monotonic()-start;after=resource.getrusage(resource.RUSAGE_CHILDREN)
 digest=hashlib.sha256((root/'.bench-bin/airbag').read_bytes()).hexdigest()
 print('BUILD_SAMPLE '+json.dumps(dict(phase=phase,iteration=iteration,seconds=elapsed,user_seconds=after.ru_utime-before.ru_utime,sys_seconds=after.ru_stime-before.ru_stime,sha256=digest)),flush=True)
 return digest
cold=build('cold',0)
for i in range(3):
 assert build('warm',i)==cold, 'unchanged build produced a different binary'
for i in range(3):
 (root/'cmd/airbag/main.go').write_text(original+'\nfunc airbagBenchmarkChange() int { return '+str(9000+i)+' }\n')
 build('incremental',i)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', required=True)
    parser.add_argument('--after', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--diagnostic', help='benchmark-only binary for filesystem/policy/audit ablations')
    parser.add_argument('--parallelism', type=int, default=2)
    parser.add_argument('--trials', type=int, default=2)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    binaries = {k: str(Path(getattr(args, k)).resolve()) for k in ('before', 'after')}
    binaries['profile'] = binaries['after']
    if args.diagnostic:
        binaries['diagnostic'] = str(Path(args.diagnostic).resolve())
    modes = {
        'baseline': [], 'fuse': ['--fs-policy'], 'exec': ['--exec-policy'],
        'both': ['--fs-policy', '--exec-policy'],
        'fuse-buffered': ['--fs-policy', '--runtime-audit=buffered'],
        'both-buffered': ['--fs-policy', '--exec-policy', '--runtime-audit=buffered'],
        'plain-fuse': ['--fs-policy'], 'policy-no-audit': ['--fs-policy'],
    }
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata = dict(type='environment', binary_sha256={name: hashlib.sha256(Path(binary).read_bytes()).hexdigest() for name, binary in binaries.items()}, kernel=platform.release(), cpu_count=os.cpu_count(), parallelism=args.parallelism, trials=args.trials, go=subprocess.check_output(['go', 'version'], text=True).strip(), source_sha=os.environ.get('BENCH_SOURCE_SHA', 'unspecified'), before_sha=os.environ.get('BENCH_BEFORE_SHA', 'unspecified'), after_sha=os.environ.get('GITHUB_SHA', 'unspecified'), conditions='CGO=0; offline module cache; empty GOCACHE per trial; OS/module caches warm; buildvcs=false; temporary compiler files in private /tmp; baseline is Airbag without runtime flags; production pairs have profiling off; profile/diagnostic variants enable instrumentation; filesystem data cache default off')
    records = []
    with output.open('w') as out:
        def emit(record):
            out.write(json.dumps(record) + '\n'); out.flush()
            print(json.dumps(record), flush=True)
        emit(metadata)
        # Pair before/after on the same runner and alternate order per trial.
        cases = [('after', 'baseline'), ('after', 'exec'), ('before', 'fuse'), ('after', 'fuse'), ('before', 'both'), ('after', 'both'), ('after', 'fuse-buffered'), ('after', 'both-buffered')]
        if args.diagnostic:
            cases += [('profile', 'fuse'), ('profile', 'fuse-buffered'), ('diagnostic', 'plain-fuse'), ('diagnostic', 'policy-no-audit')]
        for trial in range(args.trials):
            order = cases if trial % 2 == 0 else list(reversed(cases))
            for variant, mode in order:
                with tempfile.TemporaryDirectory(prefix='.airbag-build-bench.', dir=Path.home()) as temp, tempfile.TemporaryDirectory(prefix='airbag-build-state.', dir='/var/tmp') as state:
                    project = Path(temp) / 'project'
                    shutil.copytree(args.source, project)
                    (project / '.bench-driver.py').write_text(INNER)
                    subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=project, check=True)
                    subprocess.run(['git', '-c', 'user.name=Benchmark', '-c', 'user.email=bench@example.com', 'add', '-A'], cwd=project, check=True)
                    subprocess.run(['git', '-c', 'user.name=Benchmark', '-c', 'user.email=bench@example.com', 'commit', '-qm', 'fixed source'], cwd=project, check=True)
                    env = dict(os.environ, BENCH_PARALLELISM=str(args.parallelism), AIRBAG_HOME=state)
                    env.pop('AIRBAG_BENCH_RUNTIME_STAGE', None)
                    flags = list(modes[mode])
                    if variant in ('profile', 'diagnostic'):
                        flags.append('--runtime-profile')
                    if variant == 'diagnostic':
                        env['AIRBAG_BENCH_RUNTIME_STAGE'] = mode
                    before = resource.getrusage(resource.RUSAGE_CHILDREN)
                    start = time.monotonic()
                    run = subprocess.run([binaries[variant], 'run', *flags, '--', 'python3', '.bench-driver.py'], cwd=project, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    total = time.monotonic() - start
                    after = resource.getrusage(resource.RUSAGE_CHILDREN)
                    if run.returncode:
                        print(run.stdout, flush=True); print(run.stderr, flush=True)
                        raise RuntimeError(f'{variant}/{mode}/trial {trial} failed: {run.returncode}')
                    samples = [json.loads(line.removeprefix('BUILD_SAMPLE ')) for line in run.stdout.splitlines() if line.startswith('BUILD_SAMPLE ')]
                    if len(samples) != 7:
                        raise RuntimeError(f'missing build samples: {run.stdout}')
                    for sample in samples:
                        sample.update(type='build', variant=variant, mode=mode, trial=trial, parallelism=args.parallelism)
                        records.append(sample); emit(sample)
                    # log --json preserves the old/new audit schema differences.
                    events = json.loads(subprocess.check_output([binaries[variant], 'log', '--json'], cwd=project, env=env, text=True))
                    counts = {source: sum(e.get('source') == source for e in events) for source in ('fuse', 'seccomp')}
                    emit(dict(type='session', variant=variant, mode=mode, trial=trial, parallelism=args.parallelism, seconds=total, user_seconds=after.ru_utime-before.ru_utime, sys_seconds=after.ru_stime-before.ru_stime, audit_counts=counts))
                    if variant in ('profile', 'diagnostic'):
                        profiles = list(Path(state).glob('s-*/runtime-profile-*.json'))
                        if not profiles:
                            raise RuntimeError(f'missing runtime profile: {variant}/{mode}')
                        for profile in sorted(profiles):
                            emit(dict(type='runtime_profile', variant=variant, mode=mode, trial=trial, parallelism=args.parallelism, profile=json.loads(profile.read_text())))
                    subprocess.run([binaries[variant], 'discard', '--yes'], cwd=project, env=env, check=True, stdout=subprocess.DEVNULL)
        print('variant\tmode\tphase\tn\tmedian_s\tmin_s\tmax_s', flush=True)
        for variant, mode in cases:
            for phase in ('cold', 'warm', 'incremental'):
                values = [r['seconds'] for r in records if r['variant'] == variant and r['mode'] == mode and r['phase'] == phase]
                print(f'{variant}\t{mode}\t{phase}\t{len(values)}\t{statistics.median(values):.4f}\t{min(values):.4f}\t{max(values):.4f}', flush=True)


if __name__ == '__main__':
    main()
