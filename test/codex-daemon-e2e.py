import json
import fcntl
import os
import pathlib
import pty
import select
import shutil
import socket
import signal
import struct
import subprocess
import tempfile
import termios
import time


def wait_screen(fd, process, needle, captured, timeout=45):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b''
            captured.extend(chunk)
            for query, reply in [(b'\x1b[6n', b'\x1b[1;1R'), (b'\x1b]10;?', b'\x1b]10;rgb:ffff/ffff/ffff\x1b\\'), (b'\x1b]11;?', b'\x1b]11;rgb:0000/0000/0000\x1b\\')]:
                if query in chunk:
                    os.write(fd, reply)
            if needle.encode() in captured:
                return
        if process.poll() is not None:
            break
    raise AssertionError(f'missing screen {needle!r}; exit={process.poll()}; {captured.decode(errors="replace")[-8000:]}')


def wait_exit(fd, process, captured, timeout=30):
    end = time.monotonic() + timeout
    while process.poll() is None and time.monotonic() < end:
        if select.select([fd], [], [], 0.1)[0]:
            try:
                captured.extend(os.read(fd, 65536))
            except OSError:
                pass
    assert process.poll() is not None, captured.decode(errors='replace')[-8000:]
    return process.returncode


def take_terminal(slave):
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)


def main():
    repo = pathlib.Path(__file__).resolve().parent.parent
    airbag = shutil.which(os.environ.get('AIRBAG', 'airbag'))
    codex = shutil.which('codex')
    assert airbag and codex
    with tempfile.TemporaryDirectory(prefix='.airbag-daemon-e2e-', dir=os.path.expanduser('~')) as directory, tempfile.TemporaryDirectory(prefix='airbag-daemon-e2e-', dir='/var/tmp') as sessions:
        root = pathlib.Path(directory)
        home, project = root / 'home', root / 'project'
        source = home / '.codex'
        source.mkdir(parents=True)
        project.mkdir()
        (project / 'README.md').write_text('original\n')
        env = dict(os.environ, HOME=str(home), CODEX_HOME=str(source), AIRBAG_HOME=sessions, OPENAI_API_KEY='sk-mock', TERM='xterm-256color')
        env.pop('AIRBAG_SESSION', None)
        for args in [['init', '-q', '-b', 'main'], ['config', 'user.email', 'e2e@example.com'], ['config', 'user.name', 'e2e'], ['add', 'README.md'], ['commit', '-qm', 'init']]:
            subprocess.run(['git', *args], cwd=project, env=env, check=True)
        binary = source / 'packages/app-server-daemon/current/bin/codex'
        binary.parent.mkdir(parents=True)
        binary.symlink_to(codex)
        started = subprocess.run([codex, 'app-server', 'daemon', 'start'], env=env, capture_output=True, text=True, check=True, timeout=30)
        daemon = json.loads(started.stdout)
        model = tui = raw = None
        try:
            assert daemon['status'] in ('started', 'alreadyRunning', 'already-running'), daemon
            control_socket = source / 'app-server-control/app-server-control.sock'
            with socket.socket(socket.AF_UNIX) as connection:
                connection.connect(str(control_socket))
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 36, 120, 0, 0))
            raw = subprocess.Popen([airbag, 'run', '--', codex, '--dangerously-bypass-approvals-and-sandbox', '--no-alt-screen'], cwd=project, env=env, stdin=slave, stdout=slave, stderr=slave, preexec_fn=lambda: take_terminal(slave))
            os.close(slave)
            captured = bytearray()
            try:
                wait_screen(master, raw, 'app server did not become ready', captured, timeout=30)
                assert wait_exit(master, raw, captured) != 0
            finally:
                os.close(master)
            subprocess.run([airbag, 'discard', '--yes'], cwd=project, env=env, check=True, stdout=subprocess.DEVNULL)
            mock = root / 'mockapi'
            subprocess.run(['go', 'build', '-o', str(mock), './test/mockapi'], cwd=repo, check=True)
            script = root / 'calls.json'
            script.write_text(json.dumps([{'name': 'exec_command', 'input': {'cmd': 'rm README.md; echo from-codex > codex.txt'}}]))
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            model = subprocess.Popen([str(mock), '-addr', f'127.0.0.1:{port}', '-script', str(script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            end = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        break
                except OSError:
                    assert time.monotonic() < end, 'mock API did not start'
                    time.sleep(0.05)
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 36, 120, 0, 0))
            arguments = [airbag, 'codex', 'yolo', '--allow', f'tcp://127.0.0.1:{port}', '--', '--no-alt-screen', '-m', 'mock-model', '-c', 'model_provider="mock"', '-c', 'model_providers.mock.name="mock"', '-c', f'model_providers.mock.base_url="http://127.0.0.1:{port}/v1"', '-c', 'model_providers.mock.wire_api="responses"', '-c', 'model_providers.mock.env_key="OPENAI_API_KEY"', '-c', 'check_for_update_on_startup=false', '-c', 'tui.animations=false', 'do the task']
            tui = subprocess.Popen(arguments, cwd=project, env=env, stdin=slave, stdout=slave, stderr=slave, preexec_fn=lambda: take_terminal(slave))
            os.close(slave)
            captured = bytearray()
            try:
                wait_screen(master, tui, 'Folder access', captured)
                time.sleep(0.5)
                captured.clear()
                os.write(master, b'\r')
                wait_screen(master, tui, 'from-codex', captured)
                wait_screen(master, tui, 'done', captured)
                time.sleep(0.5)
                os.write(master, b'\x03')
                end = time.monotonic() + 30
                while tui.poll() is None and time.monotonic() < end:
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            captured.extend(os.read(master, 65536))
                        except OSError:
                            pass
                assert tui.poll() == 0, captured.decode(errors='replace')[-8000:]
            finally:
                os.close(master)
            assert (project / 'README.md').read_text() == 'original\n'
            assert not (project / 'codex.txt').exists()
            report = subprocess.run([airbag, 'review', '--json'], cwd=project, env=env, capture_output=True, text=True, check=True)
            changes = json.loads(report.stdout)['changes']
            assert any(c['path'] == 'README.md' and c['kind'] == 'deleted' for c in changes), changes
            assert any(c['path'] == 'codex.txt' and c['kind'] == 'added' for c in changes), changes
            with socket.socket(socket.AF_UNIX) as connection:
                connection.connect(str(control_socket))
            os.kill(daemon['pid'], 0)
            subprocess.run([airbag, 'discard', '--yes'], cwd=project, env=env, check=True, stdout=subprocess.DEVNULL)
            print('PASS: running host daemon refused; private Codex TUI completed mock task in clone')
        finally:
            for process in [raw, tui, model]:
                if process and process.poll() is None:
                    if process in (raw, tui):
                        os.killpg(process.pid, signal.SIGTERM)
                    else:
                        process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        if process in (raw, tui):
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                        process.wait(timeout=5)
            subprocess.run([codex, 'app-server', 'daemon', 'stop'], env=env, capture_output=True, check=True, timeout=30)


if __name__ == '__main__':
    main()
