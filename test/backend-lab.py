#!/usr/bin/env python3
"""Offline, benign native/runsc/Firecracker experiment; never a production backend."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import tempfile
import threading
import time


PREFIX = "AIRBAG_RESULT "
REQUIRED_CHECKS = {"host_canary_hidden", "direct_egress_denied", "built_program_runs"}
REQUIRED_PHASES = {"cold_build", "incremental_build", "compatibility_tests",
                   "small_files_2048", "exec_children_32",
                   "unchanged_build_1", "unchanged_build_2", "unchanged_build_3"}


def capture(command, log, timeout=240):
    """Keep failure logs and kill the host-side process group on timeout."""
    start = time.monotonic()
    ready = []
    lines = []
    with log.open("w") as output:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, start_new_session=True)

        def read():
            for line in proc.stdout:
                output.write(line)
                output.flush()
                lines.append(line)
                if line.strip() == "AIRBAG_READY":
                    ready.append(time.monotonic() - start)

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=15)
            raise RuntimeError(f"timeout after {timeout}s; see {log}")
        finally:
            reader.join(timeout=15)
            proc.stdout.close()
        if reader.is_alive():
            raise RuntimeError(f"output stream did not close; see {log}")
    return code, "".join(lines), time.monotonic() - start, ready


def parse_result(text):
    records = [json.loads(line.split(PREFIX, 1)[1]) for line in text.splitlines()
               if line.startswith(PREFIX)]
    if len(records) != 1:
        raise ValueError(f"expected exactly one result, got {len(records)}")
    return records[0]


def valid_result(record):
    """Missing/failed checks and partial timings must never become a pass."""
    return (record.get("status") == "passed"
            and REQUIRED_CHECKS <= record.get("checks", {}).keys()
            and all(record["checks"][key] is True for key in REQUIRED_CHECKS)
            and REQUIRED_PHASES <= record.get("phases_seconds", {}).keys()
            and all(type(record["phases_seconds"][key]) in (int, float)
                    and math.isfinite(record["phases_seconds"][key])
                    and record["phases_seconds"][key] >= 0 for key in REQUIRED_PHASES)
            and isinstance(record.get("output_sha256"), str)
            and len(record["output_sha256"]) == 64)


def tree_digest(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(str(path.relative_to(root)).encode() + b"\0")
        if path.is_symlink():
            digest.update(b"link\0" + os.readlink(path).encode())
        elif path.is_file():
            digest.update(path.read_bytes())
        digest.update(str(path.lstat().st_mode).encode() + b"\0")
    return digest.hexdigest()


def checked(command):
    subprocess.run(command, check=True, timeout=180, stdout=subprocess.DEVNULL)


def ext4(source, image, size):
    with image.open("wb") as f:
        f.truncate(size)
    checked(["mkfs.ext4", "-q", "-F", "-d", str(source), str(image)])


def oci_config(rootfs, work):
    return {
        "ociVersion": "1.0.2",
        "process": {"terminal": False, "user": {"uid": os.getuid(), "gid": os.getgid()},
                    "args": ["/probe", "--work=/work", "--go=/opt/go", "--config=/lab.json"],
                    "env": ["PATH=/opt/go/bin", "HOME=/tmp"], "cwd": "/work",
                    "noNewPrivileges": True,
                    "capabilities": {key: [] for key in
                                     ["bounding", "effective", "inheritable", "permitted", "ambient"]}},
        "root": {"path": str(rootfs), "readonly": True},
        "hostname": "airbag-lab",
        "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"},
                   {"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
                   {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
                   {"destination": "/work", "type": "bind", "source": str(work),
                    "options": ["rbind", "rw", "nosuid", "nodev"]}],
        "linux": {"namespaces": [{"type": name} for name in
                                 ["pid", "network", "ipc", "uts", "mount"]],
                  "devices": [{"path": "/dev/" + name, "type": "c", "major": 1,
                               "minor": minor, "fileMode": 438, "uid": 0, "gid": 0}
                              for name, minor in [("null", 3), ("zero", 5), ("full", 7),
                                                  ("random", 8), ("urandom", 9)]]},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="fixed vendored source snapshot")
    parser.add_argument("--go-root", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--airbag", type=Path, required=True)
    parser.add_argument("--runsc", type=Path)
    parser.add_argument("--firecracker", type=Path)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.trials <= 10:
        parser.error("trials must be between 1 and 10")
    args.output.mkdir(parents=True, exist_ok=True)
    # Must be outside HOME and /tmp: native airbag masks /tmp and readonly
    # HOME; all candidates see the identical supplied toolchain.
    lab = args.output.resolve()
    if str(lab).startswith("/tmp/"):
        parser.error("output must be outside /tmp (native airbag masks host /tmp)")
    root = lab / "rootfs"
    if root.exists():
        parser.error("use a fresh output directory")
    original = tree_digest(args.source)
    canary_fd, canary_name = tempfile.mkstemp(prefix="airbag-runtime-canary-")
    os.write(canary_fd, b"benign-host-only-canary\n")
    os.close(canary_fd)
    listener = socket.socket()
    listener.bind(("0.0.0.0", 0))
    listener.listen(16)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(("192.0.2.1", 9))  # route lookup only, no packet is sent
        host_ip = route.getsockname()[0]
    configuration = {"canary_path": canary_name,
                     "canary_addr": f"{host_ip}:{listener.getsockname()[1]}"}
    fixture_start = time.monotonic()
    for subdir in ["opt", "dev", "proc", "sys", "tmp", "work"]:
        (root / subdir).mkdir(parents=True, exist_ok=True)
    shutil.copytree(args.go_root, root / "opt" / "go", symlinks=True)
    shutil.copy2(args.probe, root / "probe")
    (root / "lab.json").write_text(json.dumps(configuration))
    rows = []
    failure = False

    def record(row):
        rows.append(row)
        # Preserve completed measurements even if CI cancels a later trial.
        with (lab / "results.jsonl").open("a") as output:
            output.write(json.dumps(row) + "\n")

    try:
        # A reachable host listener and readable canary are negative controls:
        # an unrestricted process must fail both boundary tests.
        code, text, _, _ = capture([str(args.probe), "--checks-only",
                                   "--config=" + str(root / "lab.json")], lab / "control.log")
        control = parse_result(text)
        if code == 0 or any(control.get("checks", {}).values()) or len(control.get("checks", {})) != 2:
            raise RuntimeError("negative control did not detect host access")
        record({"backend": "uncontained-control", "status": "expected-failure",
                "guest": control})
        ready = {"native": True, "gvisor": bool(args.runsc),
                 "microvm": bool(args.firecracker and args.kernel and
                                 os.access("/dev/kvm", os.R_OK | os.W_OK))}
        root_image = lab / "root.ext4"
        if ready["microvm"]:
            ext4(root, root_image, 2 * 1024**3)
        fixture_seconds = time.monotonic() - fixture_start
        for trial in range(args.trials):
            order = ["native", "gvisor", "microvm"]
            order = order[trial % 3:] + order[:trial % 3]
            for backend in order:
                row = {"backend": backend, "trial": trial + 1,
                       "profile": "offline-workspace-lab-v1", "status": "failed"}
                if not ready[backend]:
                    row.update(status="unavailable", reason="missing executable, kernel or writable /dev/kvm")
                    record(row)
                    failure = True
                    continue
                case = lab / f"{backend}-{trial+1}"
                work = case / "work"
                preparation = time.monotonic()
                shutil.copytree(args.source, work, symlinks=True)
                command = []
                cleanup = None
                if backend == "native":
                    sessions = case / "sessions"
                    command = ["env", "AIRBAG_HOME=" + str(sessions), str(args.airbag),
                               "run", "--no-home", "--strict", "--", str(root / "probe"),
                               "--work=" + str(work), "--go=" + str(root / "opt" / "go"),
                               "--config=" + str(root / "lab.json")]
                    # cwd is explicit through a host wrapper, never shell text.
                    command = ["python3", "-c", "import os,sys; os.chdir(sys.argv[1]); os.execvp(sys.argv[2],sys.argv[2:])", str(work)] + command
                elif backend == "gvisor":
                    container = f"airbag-lab-{os.getpid()}-{trial}"
                    state = case / "state"
                    (case / "config.json").write_text(json.dumps(oci_config(root, work)))
                    common = ["sudo", str(args.runsc), "--root=" + str(state)]
                    command = common + ["--platform=systrap", "--network=none",
                                        "--file-access=exclusive", "run", "--bundle=" + str(case), container]
                    cleanup = common + ["delete", "--force", container]
                else:
                    image = case / "work.ext4"
                    ext4(work, image, 4 * 1024**3)
                    vm_config = {
                        "boot-source": {"kernel_image_path": str(args.kernel.resolve()),
                                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/probe"},
                        "drives": [{"drive_id": "rootfs", "path_on_host": str(root_image),
                                    "is_root_device": True, "is_read_only": True},
                                   {"drive_id": "work", "path_on_host": str(image),
                                    "is_root_device": False, "is_read_only": False}],
                        "machine-config": {"vcpu_count": 1, "mem_size_mib": 2048},
                    }
                    config_path = case / "firecracker.json"
                    config_path.write_text(json.dumps(vm_config))
                    command = [str(args.firecracker), "--no-api", "--config-file", str(config_path)]
                row["prepare_seconds"] = time.monotonic() - preparation
                try:
                    code, text, elapsed, started = capture(command, case / "console.log")
                    guest = parse_result(text)
                    row.update(guest=guest, exit_code=code, execution_seconds=elapsed,
                               startup_seconds=started[0] if len(started) == 1 else None)
                    # native lower must stay untouched; candidate input copies
                    # are intentionally writable and are not the original tree.
                    preserved = tree_digest(args.source) == original
                    if backend == "native":
                        preserved = preserved and tree_digest(work) == original
                    row["host_source_unchanged"] = preserved
                    if code == 0 and len(started) == 1 and valid_result(guest) and preserved:
                        row["status"] = "passed"
                    else:
                        failure = True
                except (ValueError, RuntimeError, OSError) as error:
                    row["error"] = str(error)
                    failure = True
                finally:
                    if cleanup:
                        subprocess.run(cleanup, timeout=30, check=False, stdout=subprocess.DEVNULL)
                record(row)
                print(json.dumps(row), flush=True)
        metadata = {"host_kernel": os.uname().release, "source_sha256": original,
                    "host_architecture": os.uname().machine, "host_cpu_count": os.cpu_count(),
                    "fixture_seconds": fixture_seconds,
                    "cpu_parallelism": 1, "microvm_memory_mib": 2048,
                    "equivalent_full_airbag_policy": False,
                    "guest_telemetry_is_attestation": False,
                    "notes": "runsc/microVM are bare candidates; no Airbag proxy, HOME branch or FUSE/exec audit integration"}
        (lab / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    finally:
        listener.close()
        Path(canary_name).unlink(missing_ok=True)
        (lab / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    raise SystemExit(1 if failure else 0)


if __name__ == "__main__":
    main()
