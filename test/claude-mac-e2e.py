import fcntl
import json
import os
import pathlib
import pty
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import termios
import time


def screen(data):
    return re.sub(rb'\s', b'', re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]', b'', data))


def drain(fd, process, timeout):
    end = time.monotonic() + timeout
    while process.poll() is None and time.monotonic() < end:
        if select.select([fd], [], [], .1)[0]:
            try:
                os.read(fd, 65536)
            except OSError:
                break


def main():
    repo = pathlib.Path(__file__).resolve().parent.parent
    airbag = shutil.which(os.environ.get('AIRBAG', 'airbag'))
    claude = shutil.which('claude')
    assert airbag and claude
    with tempfile.TemporaryDirectory(prefix='.airbag-claude-mac-', dir=os.path.expanduser('~')) as directory, tempfile.TemporaryDirectory(prefix='airbag-claude-mac-', dir='/var/tmp') as sessions:
        root = pathlib.Path(directory)
        home, project = root / 'home', root / 'project'
        home.mkdir()
        project.mkdir()
        (project / 'README.md').write_text('original\n')
        (home / 'canary.txt').write_text('original\n')
        (home / '.claude').mkdir()
        (home / '.claude.json').write_text(json.dumps({'hasCompletedOnboarding': True, 'customApiKeyResponses': {'approved': ['sk-ant-mock'], 'rejected': []}}))
        (home / '.claude/settings.json').write_text(json.dumps({'theme': 'dark', 'spinnerTipsEnabled': False, 'prefersReducedMotion': True}))
        keys = ['PATH', 'USER', 'LOGNAME']
        env = {key: os.environ[key] for key in keys if key in os.environ}
        env.update(HOME=str(home), SHELL='/bin/bash', AIRBAG_HOME=sessions, TERM='xterm-256color', ANTHROPIC_API_KEY='sk-ant-mock', DISABLE_AUTOUPDATER='1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1', CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN='1', CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT='1', CLAUDE_CODE_TMPDIR=str(root / 'forbidden-temp'), CLAUDE_SECURESTORAGE_CONFIG_DIR=str(home / '.claude'))
        for args in [['init', '-q', '-b', 'main'], ['config', 'user.email', 'e2e@example.com'], ['config', 'user.name', 'e2e'], ['add', 'README.md'], ['commit', '-qm', 'init']]:
            subprocess.run(['git', *args], cwd=project, env=env, check=True)
        remote = root / 'remote.git'
        subprocess.run(['git', 'init', '-q', '--bare', str(remote)], env=env, check=True)
        subprocess.run(['git', 'remote', 'add', 'origin', str(remote)], cwd=project, env=env, check=True)
        subprocess.run(['git', 'push', '-q', 'origin', 'main'], cwd=project, env=env, check=True)
        original_head = subprocess.check_output(['git', '--git-dir', str(remote), 'rev-parse', 'main'], env=env)
        project_head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=project, env=env)
        project_status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=project, env=env)
        mock = root / 'mockapi'
        subprocess.run(['go', 'build', '-o', str(mock), './test/mockapi'], cwd=repo, check=True)
        calls = root / 'calls.json'
        task = 'echo from-claude > claude.txt; git add -A && git commit -qm "mock work" && git push origin main'
        calls.write_text(json.dumps([{'name': 'Bash', 'input': {'command': task, 'description': 'write and queue push'}}]))
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        model = subprocess.Popen([str(mock), '-addr', f'127.0.0.1:{port}', '-script', str(calls)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process = master = None
        try:
            end = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    assert time.monotonic() < end, 'mock API did not start'
                    time.sleep(.05)
            env['ANTHROPIC_BASE_URL'] = f'http://127.0.0.1:{port}'
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 36, 120, 0, 0))

            def terminal():
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

            argv = [airbag, 'run', '--allow', f'tcp://127.0.0.1:{port}', '--', claude, '--dangerously-skip-permissions', '--model', 'mock-model']
            process = subprocess.Popen(argv, cwd=project, env=env, stdin=slave, stdout=slave, stderr=slave, preexec_fn=terminal)
            os.close(slave)
            captured, stages = bytearray(), set()
            end = time.monotonic() + 60
            completed = False
            while process.poll() is None and time.monotonic() < end:
                if not select.select([master], [], [], .1)[0]:
                    continue
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                captured.extend(chunk)
                if b'\x1b[6n' in chunk:
                    os.write(master, b'\x1b[1;1R')
                plain = screen(captured)
                assert b'EPERM' not in plain, captured.decode(errors='replace')[-5000:]
                assert b'Loginexpired' not in plain, captured.decode(errors='replace')[-5000:]
                for stage, needle in [('trust', b'Yes,Itrustthisfolder'), ('accept', b'Yes,Iaccept')]:
                    if needle in plain and stage not in stages:
                        time.sleep(.3)
                        os.write(master, b'\x1b[B\r')
                        stages.add(stage)
                if b'mock-model' in plain and 'bang' not in stages:
                    time.sleep(.4)
                    os.write(master, b'! echo from-bang > bang.txt\r')
                    stages.add('bang')
                clones = list(pathlib.Path(sessions).glob('s-*/ws/clone'))
                if clones and (clones[0] / 'bang.txt').exists() and (clones[0] / 'claude.txt').exists() and b'done' in plain:
                    completed = True
                    break
            assert completed, captured.decode(errors='replace')[-7000:]
            os.write(master, b'\x03')
            time.sleep(.4)
            os.write(master, b'\x03')
            drain(master, process, 15)
            assert process.poll() == 0, f'exit={process.poll()}, want 0'
            assert (project / 'README.md').read_text() == 'original\n'
            assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=project, env=env) == project_head, 'host project HEAD changed'
            assert subprocess.check_output(['git', 'status', '--porcelain'], cwd=project, env=env) == project_status, 'host project index changed'
            assert not (project / 'bang.txt').exists()
            assert not (project / 'claude.txt').exists()
            assert (home / 'canary.txt').read_text() == 'original\n'
            assert not (root / 'forbidden-temp').exists()
            assert subprocess.check_output(['git', '--git-dir', str(remote), 'rev-parse', 'main'], env=env) == original_head, 'host remote changed'
            report = json.loads(subprocess.check_output([airbag, 'review', '--json'], cwd=project, env=env))
            for path in ['bang.txt', 'claude.txt']:
                assert any(c['path'] == path and c['kind'] == 'added' for c in report['changes']), report['changes']
            intents = report['outbox']
            assert len(intents) == 1 and intents[0]['argv'] == ['git', 'push', 'origin', 'main'] and intents[0]['status'] == 'pending', intents
            temps = list(pathlib.Path(sessions).glob('s-*/tmp/claude-*'))
            assert temps, 'Claude temp files were not created in the session'
            subprocess.run([airbag, 'discard', '--yes'], cwd=project, env=env, check=True, stdout=subprocess.DEVNULL)
            print('PASS: Claude bang command, Bash tool, mock authentication and push outbox on macOS')
        finally:
            if process and process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            if master is not None:
                os.close(master)
            if process:
                process.wait(timeout=5)
            model.terminate()
            model.wait(timeout=5)


if __name__ == '__main__':
    main()
