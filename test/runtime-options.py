#!/usr/bin/env python3
"""Real Airbag host policy + gVisor/Firecracker integration, benign fixtures."""
import argparse
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['airbag', 'probe', 'runsc', 'firecracker', 'kernel', 'go-root', 'output']:
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    lab = a.output.resolve()
    lab.mkdir(parents=True)
    root = lab / 'trusted-rootfs'
    for d in ['dev', 'proc', 'sys', 'tmp', 'run', 'usr/local', 'bin']:
        (root / d).mkdir(parents=True, exist_ok=True)
    shutil.copytree(a.go_root, root / 'usr/local/go', symlinks=True)
    shutil.copy2(a.probe, root / 'probe')
    # The static guest check invokes the deferred shim directly, so it needs
    # no host shell, libc, agent login or real third-party service.
    cert, key = lab / 'server.pem', lab / 'server.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1',
                    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
                   check=True, capture_output=True)
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            value = self.headers.get('Authorization', '')
            seen.append(value)
            self.send_response(200 if value == 'Bearer benign-runtime-bound-token' else 401)
            self.end_headers()
            self.wfile.write(value.encode())

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(('192.0.2.1', 9))
        host_ip = route.getsockname()[0]
    canary = lab / 'host-canary'
    canary.write_text('benign host-only content\n')
    rows = []
    try:
        for backend in ['gvisor', 'microvm']:
            case = lab / backend
            work, home, sessions = case / 'workspace', case / 'home', case / 'sessions'
            work.mkdir(parents=True)
            (home / '.config/airbag').mkdir(parents=True)
            (work / 'seed.txt').write_text('original\n')
            (work / 'removed.txt').write_text('original\n')
            (work / 'airbag.yaml').write_text('defer:\n  - publisher send\n')
            (home / '.config/airbag/airbag.yaml').write_text('''credentials:
  - name: check
    hosts: [127.0.0.1]
    source: env:BOUND_SOURCE_TOKEN
    env: [CHECK_TOKEN]
rules:
  - name: runtime-deny-localhost
    when: effect.kind == "net.connect" && effect.target == "localhost"
    verdict: deny
''')
            port = server.server_port
            (root / 'check.json').write_text(json.dumps({
                'Canary': str(canary), 'Original': str(work), 'Address': f'{host_ip}:{port}',
                'TLSURL': f'https://127.0.0.1:{port}/', 'DeniedURL': f'http://localhost:{port}/'}))
            env = {'PATH': os.environ['PATH'], 'HOME': str(home), 'AIRBAG_HOME': str(sessions),
                   'BOUND_SOURCE_TOKEN': 'benign-runtime-bound-token', 'SSL_CERT_FILE': str(cert)}
            flags = ['--backend=' + backend, '--require-isolation=' +
                     ('application-kernel' if backend == 'gvisor' else 'virtual-machine'),
                     '--no-home', '--strict', '--runtime-rootfs=' + str(root),
                     '--runtime-bin=' + str((a.runsc if backend == 'gvisor' else a.firecracker).resolve()),
                     '--allow=127.0.0.1:' + str(port), '--allow=localhost:' + str(port)]
            if backend == 'microvm':
                flags += ['--runtime-kernel=' + str(a.kernel.resolve())]

            def call(*args, timeout=300):
                return subprocess.run([str(a.airbag.resolve()), *args], cwd=work, env=env,
                                      capture_output=True, text=True, timeout=timeout)

            row = {'backend': backend, 'status': 'failed'}
            before = len(seen)
            start = time.monotonic()
            proc = call('run', *flags, '--', '/probe')
            row['run_seconds'] = time.monotonic() - start
            (case / 'run.log').write_text(proc.stdout + proc.stderr)
            if proc.returncode:
                row['error'] = f'run exited {proc.returncode}; see run.log'
                rows.append(row)
                continue
            checks = [json.loads(x.split(' ', 1)[1]) for x in proc.stdout.splitlines()
                      if x.startswith('RUNTIME_CHECK ')]
            assert len(checks) == 1 and all(checks[0].values())
            row['checks'] = checks[0]
            row['cold_build_seconds'] = float(next(x.split()[1] for x in proc.stdout.splitlines()
                                                  if x.startswith('BUILD_SECONDS ')))
            metas = list(sessions.glob('s-*/meta.json'))
            assert len(metas) == 1
            sid = json.loads(metas[0].read_text())['id']
            assert (work / 'seed.txt').read_text() == 'original\n'
            assert not (work / 'result.txt').exists() and not (work / 'escaped').exists()
            review = call('review', sid, '--json')
            (case / 'review.json').write_text(review.stdout)
            assert review.returncode == 0 and 'result.txt' in review.stdout and 'publisher' in review.stdout
            effects = call('log', sid)
            (case / 'effects.log').write_text(effects.stdout)
            assert 'runtime-deny-localhost' in effects.stdout
            assert 'benign-runtime-bound-token' not in effects.stdout
            # Resume cannot silently change provider or downgrade the saved requirement.
            meta_before = metas[0].read_bytes()
            downgrade = call('run', '--session=' + sid, '--', 'true')
            assert downgrade.returncode != 0 and metas[0].read_bytes() == meta_before
            resume = call('run', *flags, '--session=' + sid, '--', '/probe', 'resume')
            (case / 'resume.log').write_text(resume.stdout + resume.stderr)
            assert resume.returncode == 0
            assert len(seen) - before == 2
            # Apply only files; do not execute the deliberately nonexistent publisher.
            applied = call('apply', sid, '--yes', '--only=seed.txt,result.txt,main.go,built,removed.txt')
            (case / 'apply.log').write_text(applied.stdout + applied.stderr)
            assert applied.returncode == 0
            assert (work / 'seed.txt').read_text() == 'changed in guest\n'
            assert (work / 'result.txt').read_text() == 'reviewable output\n'
            assert not (work / 'removed.txt').exists()
            row.update(status='passed', host_source_unchanged_before_apply=True,
                       resume_passed=True, explicit_apply_passed=True,
                       host_observed_credential_requests=len(seen) - before)
            rows.append(row)
            print(json.dumps(row), flush=True)
    finally:
        server.shutdown()
        server.server_close()
        (lab / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    return 0 if len(rows) == 2 and all(r['status'] == 'passed' for r in rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
