#!/usr/bin/env python3
"""Benign AgentFS release/mount compatibility probe, not a security benchmark."""
import argparse
from contextlib import closing
import fcntl
import json
import mmap
import os
from pathlib import Path
import platform
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time


def workload():
    root = Path.cwd()
    checks = {}

    def check(name, operation):
        start = time.monotonic()
        try:
            operation()
            checks[name] = {"passed": True, "seconds": time.monotonic() - start}
        except (OSError, AssertionError, subprocess.SubprocessError) as error:
            checks[name] = {"passed": False, "error": str(error)}
            if isinstance(error, subprocess.CalledProcessError):
                checks[name]["stderr"] = error.stderr

    def cow():
        assert (root / "seed.txt").read_text() == "original\n"
        (root / "seed.txt").write_text("changed\n")
        (root / "removed.txt").unlink()
        assert not (root / "removed.txt").exists()

    def basic():
        file = root / "new.txt"
        with file.open("wb") as out:
            out.write(b"hello mounted filesystem\n")
            out.flush()
            os.fsync(out.fileno())
        assert file.stat().st_size == 25
        file.rename(root / "renamed.txt")
        assert (root / "renamed.txt").read_bytes() == b"hello mounted filesystem\n"

    def aliases():
        file = root / "alias-source"
        file.write_text("alias\n")
        os.link(file, root / "hardlink")
        os.symlink("alias-source", root / "symlink")
        assert (root / "hardlink").read_text() == (root / "symlink").read_text() == "alias\n"
        file.unlink()
        assert (root / "hardlink").read_text() == "alias\n"

    def mapping():
        file = root / "mapped"
        file.write_bytes(b"mapped bytes")
        with file.open("rb") as inp, mmap.mmap(inp.fileno(), 0, access=mmap.ACCESS_READ) as view:
            assert view[:] == b"mapped bytes"

    def locks():
        # NFS locallocks may satisfy this without any server-side lock policy.
        with (root / "lock").open("w") as out:
            fcntl.flock(out, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(out, fcntl.LOCK_UN)

    def readonly_object():
        # Git's loose-object pattern: create, write, chmod 0444, close, rename.
        file = root / "object.tmp"
        with file.open("wb") as out:
            out.write(b"object bytes")
            out.flush()
            os.fchmod(out.fileno(), 0o444)
        file.rename(root / "object")
        assert (root / "object").read_bytes() == b"object bytes"

    def fsync_before_chmod():
        # Diagnostic only: force NFS writeback before making the file readonly.
        # A pass here never substitutes for the actual Git/object pattern.
        file = root / "object-synced.tmp"
        with file.open("wb") as out:
            out.write(b"object bytes")
            out.flush()
            os.fsync(out.fileno())
            os.fchmod(out.fileno(), 0o444)
        file.rename(root / "object-synced")
        assert (root / "object-synced").read_bytes() == b"object bytes"

    def git():
        for argv in [["git", "init", "-q"], ["git", "add", "seed.txt"],
                     ["git", "-c", "user.name=Filesystem Probe", "-c", "user.email=probe@example.invalid",
                      "-c", "commit.gpgsign=false", "commit", "-qm", "local fixture"],
                     ["git", "fsck", "--no-reflogs"]]:
            subprocess.run(argv, check=True, capture_output=True, text=True, timeout=60)

    def git_fsync():
        directory = root / "diagnostic-git-fsync"
        directory.mkdir()
        (directory / "fixture.txt").write_text("local Git fsync diagnostic\n")
        config = ["git", "-c", "core.fsync=loose-object", "-c", "core.fsyncMethod=fsync"]
        for argv in [config + ["init", "-q"], config + ["add", "fixture.txt"],
                     config + ["-c", "user.name=Filesystem Probe", "-c", "user.email=probe@example.invalid",
                               "-c", "commit.gpgsign=false", "commit", "-qm", "local fixture"],
                     config + ["fsck", "--no-reflogs"]]:
            subprocess.run(argv, cwd=directory, check=True, capture_output=True, text=True, timeout=60)

    mounts = subprocess.run(["mount"], capture_output=True, text=True, check=True).stdout
    mounted = any(str(root) in line and ("fuse" in line.lower() or "nfs" in line.lower())
                  for line in mounts.splitlines())
    checks["real_mount"] = {"passed": mounted, "cwd": str(root),
                            "mount": [line for line in mounts.splitlines() if str(root) in line]}
    for name, operation in [("cow", cow), ("create_fsync_stat_rename_read", basic),
                            ("hardlink_symlink", aliases), ("mmap_read", mapping),
                            ("local_flock", locks), ("readonly_object", readonly_object),
                            ("git_commit_fsck", git)]:
        check(name, operation)
    required_pass = all(value["passed"] for value in checks.values())
    check("diagnostic_fsync_before_chmod", fsync_before_chmod)
    check("diagnostic_git_fsync", git_fsync)
    print("AGENTFS_PROBE " + json.dumps(checks), flush=True)
    return 0 if required_pass else 1


def mounted_workload(binary, db, home, env, backend, output):
    """Test explicit mount separately from the release's exec/overlay failure."""
    point = home / "mnt"
    point.mkdir()
    command = [binary, "mount", "--foreground", "--backend", backend, str(db), str(point)]
    with (output / "mount-server.log").open("w") as log:
        server = subprocess.Popen(command, cwd=home, env=env, stdout=log,
                                  stderr=subprocess.STDOUT, start_new_session=True)
        mounted = False
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                mounts = subprocess.run(["mount"], capture_output=True, text=True, check=True).stdout
                if any(str(point) in line and ("fuse" in line.lower() or "nfs" in line.lower())
                       for line in mounts.splitlines()):
                    mounted = True
                    break
                if server.poll() is not None:
                    raise RuntimeError("mount server exited; see mount-server.log")
                time.sleep(0.1)
            if not mounted:
                raise RuntimeError("mount not ready in 15s; see mount-server.log")
            return subprocess.run([sys.executable, str(Path(__file__).resolve()), "--workload"],
                                  cwd=point, env=env, capture_output=True, text=True, timeout=180)
        finally:
            if mounted:
                unmount = ["/sbin/umount", str(point)] if sys.platform == "darwin" else ["fusermount3", "-u", str(point)]
                cleanup = subprocess.run(unmount, capture_output=True, text=True, timeout=30)
                (output / "unmount.log").write_text(cleanup.stdout + cleanup.stderr)
            if server.poll() is None:
                os.killpg(server.pid, signal.SIGTERM)
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(server.pid, signal.SIGKILL)
                    server.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentfs", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--workload", action="store_true")
    parser.add_argument("--cli-only", action="store_true")
    args = parser.parse_args()
    if args.workload:
        return workload()
    if not args.agentfs or not args.output:
        parser.error("--agentfs and --output required")
    args.output.mkdir(parents=True, exist_ok=True)
    result = {"platform": platform.platform(), "architecture": platform.machine(),
              "mounted": False, "security_equivalence_tested": False,
              "durability_equivalence_tested": False}
    try:
        with tempfile.TemporaryDirectory(prefix="airbag-agentfs-probe-") as private:
            home = Path(private)
            base = home / "base"
            base.mkdir()
            (base / "seed.txt").write_text("original\n")
            (base / "removed.txt").write_text("original\n")
            env = {"PATH": os.environ["PATH"], "HOME": private, "TMPDIR": private}
            binary = str(args.agentfs.resolve())

            def cli(*argv):
                return subprocess.run([binary, *argv], cwd=home, env=env, check=True,
                                      capture_output=True, text=True, timeout=180)

            result["version"] = cli("--version").stdout.strip()
            cli("init", "--base", str(base), "probe")
            db = home / ".agentfs" / "probe.db"
            cli("fs", str(db), "write", "cli.txt", "hello")
            result["cli_read_back"] = cli("fs", str(db), "cat", "cli.txt").stdout.strip()
            assert result["cli_read_back"] == "hello"
            with closing(sqlite3.connect(db)) as conn:
                result["tool_calls_after_cli_read_write"] = conn.execute("SELECT count(*) FROM tool_calls").fetchone()[0]
            if not args.cli_only:
                backend = "nfs" if sys.platform == "darwin" else "fuse"
                result["backend"] = backend
                # Preserve exec's independent outcome; do not silently report
                # an explicit mount as a successful exec invocation.
                start = time.monotonic()
                execution = subprocess.run([binary, "exec", "--backend", backend, str(db), "/usr/bin/true"],
                                           cwd=home, env=env, capture_output=True, text=True, timeout=60)
                result["exec_overlay"] = {"passed": execution.returncode == 0,
                                          "exit_code": execution.returncode,
                                          "seconds": time.monotonic() - start}
                (args.output / "exec-overlay.log").write_text(execution.stdout + execution.stderr)
                result["mount_method"] = "mount-foreground"
                start = time.monotonic()
                proc = mounted_workload(binary, db, home, env, backend, args.output)
                result["mount_and_workload_seconds"] = time.monotonic() - start
                (args.output / "mount.log").write_text(proc.stdout + proc.stderr)
                records = [json.loads(line.split(" ", 1)[1]) for line in proc.stdout.splitlines()
                           if line.startswith("AGENTFS_PROBE ")]
                result["exit_code"] = proc.returncode
                if len(records) != 1:
                    raise RuntimeError("mounted workload did not emit one result; see mount.log")
                result["checks"] = records[0]
                result["mounted"] = records[0]["real_mount"]["passed"]
                result["host_base_unchanged"] = all((base / name).read_text() == "original\n"
                                                    for name in ["seed.txt", "removed.txt"])
                with closing(sqlite3.connect(db)) as conn:
                    result["tool_calls_after_mounted_operations"] = conn.execute("SELECT count(*) FROM tool_calls").fetchone()[0]
                if proc.returncode != 0 or not result["host_base_unchanged"]:
                    raise RuntimeError("mounted compatibility check failed; see checks and mount.log")
            result["status"] = "cli-only" if args.cli_only else "passed"
    except (OSError, AssertionError, RuntimeError, subprocess.SubprocessError, sqlite3.Error) as error:
        result.update(status="failed", error=str(error))
        if isinstance(error, subprocess.CalledProcessError):
            (args.output / "command-error.log").write_text((error.stdout or "") + (error.stderr or ""))
    (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
