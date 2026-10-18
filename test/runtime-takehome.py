#!/usr/bin/env python3
"""Airbag VM backends vs a simulated malicious take-home repository.

A developer clones a take-home assignment and runs its setup step under
airbag's microVM/gVisor backend. The setup (test/runtimecheck/takehome)
behaves like fake-recruiter take-home malware against canaries only. This
harness proves airbag contains every step: the host SSH key and token
stay hidden, exfil and a direct host dial fail, persistence lands only in
the private copy, review flags the git hook, and the canary strings never
reach any log or the review JSON. Then it discards the session.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import traceback

# Canaries the guest must never obtain or leak.
SSH_CANARY = 'airbag-canary: not a key\n'
# Named and sized like a credential, so airbag drops it from the guest.
TOKEN_CANARY = 'airbag-canary-github-token-DO-NOT-USE'
# The host .bashrc the guest's persistence must not be able to change.
BASHRC_CANARY = '# airbag take-home canary bashrc; must stay exactly this\n'
EXFIL_HOST = 'exfil.invalid'


def git(work, *args):
    # A hermetic repository: no host git identity or config leaks in, and
    # none is needed, so the committed tree looks like a fresh clone.
    env = {**os.environ, 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull,
           'GIT_AUTHOR_NAME': 'Take Home', 'GIT_AUTHOR_EMAIL': 'takehome@example.com',
           'GIT_COMMITTER_NAME': 'Take Home', 'GIT_COMMITTER_EMAIL': 'takehome@example.com'}
    subprocess.run(['git', '-C', str(work), *args], check=True, capture_output=True, text=True, env=env)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['airbag', 'runsc', 'firecracker', 'kernel', 'go-root', 'takehome', 'output']:
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    lab = a.output.resolve()
    lab.mkdir(parents=True)
    root = lab / 'trusted-rootfs'
    for d in ['dev', 'proc', 'sys', 'tmp', 'run', 'usr/local', 'bin']:
        (root / d).mkdir(parents=True, exist_ok=True)
    # The guest compiles and runs the cloned repo's own setup; it needs a
    # Go toolchain in the trusted image, nothing else.
    shutil.copytree(a.go_root, root / 'usr/local/go', symlinks=True)

    # A direct-egress negative control: a listener reachable from the host
    # on its real address. If the guest's direct dial to it fails but the
    # host's succeeds, the sandbox is what blocked it, not an unroutable
    # address.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', 0))
    listener.listen(16)
    direct_port = listener.getsockname()[1]

    def accept_loop():
        while True:
            try:
                conn, _ = listener.accept()
                conn.close()
            except OSError:
                return
    threading.Thread(target=accept_loop, daemon=True).start()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(('192.0.2.1', 9))
        host_ip = route.getsockname()[0]
    direct_address = f'{host_ip}:{direct_port}'
    with socket.create_connection((host_ip, direct_port), timeout=5):
        pass
    (lab / 'negative-controls-takehome.json').write_text(json.dumps({
        'direct_address_reachable': True,
        'token_canary_set_in_host_env': True,
        'ssh_canary_readable_on_host': True}) + '\n')

    rows = []
    try:
        # At least microVM and gVisor, both strict: the boundary must hold
        # under the strongest profile either backend offers.
        for backend, strict in [('gvisor', True), ('microvm', True)]:
            case = lab / (backend + ('-strict' if strict else ''))
            work, home, sessions = case / 'workspace', case / 'home', case / 'sessions'
            work.mkdir(parents=True)
            (home / '.ssh').mkdir(parents=True)
            (home / '.config/airbag').mkdir(parents=True)
            ssh_key = home / '.ssh/id_ed25519'
            ssh_key.write_text(SSH_CANARY)
            ssh_key.chmod(0o600)
            bashrc = home / '.bashrc'
            bashrc.write_text(BASHRC_CANARY)
            assert ssh_key.read_text() == SSH_CANARY  # readable on the host
            # Assemble the cloned repo: the take-home source, then history.
            shutil.copytree(a.takehome, work, dirs_exist_ok=True)
            git(work, 'init', '-b', 'main')
            git(work, 'add', '-A')
            git(work, 'commit', '-m', 'take-home assignment skeleton')
            # Host-specific canary coordinates for the guest payload.
            (root / 'check.json').write_text(json.dumps({
                'HostSSHKeyPath': str(ssh_key), 'DirectAddress': direct_address}))
            # The token is set like a developer's shell would; airbag must
            # keep it out of the guest. GO* make `go run` offline and
            # hermetic (the toolchain is local; no module fetch).
            env = {'PATH': os.environ['PATH'], 'HOME': str(home), 'AIRBAG_HOME': str(sessions),
                   'GITHUB_TOKEN': TOKEN_CANARY, 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off',
                   'GOSUMDB': 'off', 'CGO_ENABLED': '0'}
            flags = ['--backend=' + backend, '--require-isolation=' +
                     ('application-kernel' if backend == 'gvisor' else 'virtual-machine'),
                     '--no-home', '--runtime-rootfs=' + str(root),
                     '--runtime-bin=' + str((a.runsc if backend == 'gvisor' else a.firecracker).resolve())]
            if strict:
                flags += ['--strict']
            if backend == 'microvm':
                flags += ['--runtime-kernel=' + str(a.kernel.resolve())]

            def call(*args, timeout):
                return subprocess.run([str(a.airbag.resolve()), *args], cwd=work, env=env,
                                      capture_output=True, text=True, timeout=timeout)

            row = {'backend': backend, 'strict': strict, 'status': 'failed'}
            rows.append(row)
            try:
                # A cold build of net/http in a 1 vCPU microVM is slow; the
                # timeout is generous and the wall time is measured.
                start = time.monotonic()
                proc = call('run', *flags, '--', '/usr/local/go/bin/go', 'run', './cmd/setup',
                            timeout=900 if backend == 'microvm' else 600)
                row['run_seconds'] = time.monotonic() - start
                (case / 'run.log').write_text(proc.stdout + proc.stderr)
                if proc.returncode:
                    row['error'] = f'run exited {proc.returncode}; see run.log'
                    continue
                checks = [json.loads(x.split(' ', 1)[1]) for x in proc.stdout.splitlines()
                          if x.startswith('TAKEHOME_CHECK ')]
                assert len(checks) == 1, 'expected exactly one TAKEHOME_CHECK line'
                row['observations'] = checks[0]
                assert all(checks[0].values()), f'the guest reported a boundary gap: {checks[0]}'

                metas = list(sessions.glob('s-*/meta.json'))
                assert len(metas) == 1
                meta = json.loads(metas[0].read_text())
                sid = meta['id']
                assert meta.get('egress') == 'allowlist-proxy', meta.get('egress')

                review = call('review', sid, '--json', timeout=120)
                (case / 'review.json').write_text(review.stdout)
                assert review.returncode == 0
                report = json.loads(review.stdout)
                hook = next((c for c in report['changes'] if c['path'] == '.git/hooks/post-checkout'), None)
                assert hook is not None, 'review did not list the planted git hook'
                assert 'persist' in hook.get('flags', []), f'git hook not flagged persist: {hook}'
                row['persist_change'] = hook

                effects = call('log', sid, timeout=120)
                (case / 'effects.log').write_text(effects.stdout)
                denied = report.get('network', {}).get('denied', {})
                exfil_targets = [k for k in denied if EXFIL_HOST in k]
                assert exfil_targets or EXFIL_HOST in effects.stdout, 'exfil denial not recorded'
                row['exfil_denied_targets'] = exfil_targets

                # Containment, checked on the host before any apply.
                assert bashrc.read_text() == BASHRC_CANARY, 'host .bashrc changed before apply'
                assert not (work / '.git/hooks/post-checkout').exists(), 'persistence escaped to the host'
                for name in ['run.log', 'effects.log', 'review.json']:
                    text = (case / name).read_text()
                    assert SSH_CANARY.strip() not in text, f'{name} leaked the ssh canary'
                    assert TOKEN_CANARY not in text, f'{name} leaked the token canary'

                discarded = call('discard', sid, '--yes', timeout=120)
                (case / 'discard.log').write_text(discarded.stdout + discarded.stderr)
                assert discarded.returncode == 0, 'discard failed'
                assert not metas[0].parent.exists(), 'discard left the session'
                row['status'] = 'passed'
                print(json.dumps(row), flush=True)
            except (OSError, AssertionError, ValueError, subprocess.SubprocessError) as error:
                row['error'] = str(error) or type(error).__name__
                (case / 'error.log').write_text(traceback.format_exc())
    finally:
        listener.close()
        (lab / 'results-takehome.json').write_text(json.dumps(rows, indent=2) + '\n')
    return 0 if len(rows) == 2 and all(r['status'] == 'passed' for r in rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
