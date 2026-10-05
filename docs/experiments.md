# Experiments

Two experiments ran on 2026-10-05 and were not merged: they answer a
question, they do not change airbag. Their branches keep the harness, the
raw data and the full write-ups; this page keeps what they found.

## Stronger execution backends (PR #19)

Branch `experiment/execution-backends`; write-up `docs/backend-experiment.md`,
raw data `testdata/backend-lab/2026-10-05/`.

The question: is a stronger boundary than airbag's namespaces affordable for an
offline coding workflow? On a GitHub-hosted Ubuntu 24.04 runner (x86_64, 4 CPUs,
`/dev/kvm` present) it built and tested a fixed airbag snapshot, vendored and
offline, under three candidates: native airbag (strict, no `$HOME`), gVisor
`runsc` (systrap, no network) and Firecracker (no network device, 1 vCPU, ext4).
Each candidate had to keep a host canary unreadable, refuse direct egress and
leave the source unchanged; an unrestricted control failed both checks.

Medians of two trials, in seconds:

| | cold build | unchanged build | incremental | ready | whole run |
|---|---:|---:|---:|---:|---:|
| native | 44.8 | 0.81 | 0.93 | 0.04 | 63.3 |
| gVisor | 62.9 | 1.49 | 1.69 | 0.06 | 90.0 |
| Firecracker | 47.5 | 0.82 | 0.93 | 0.85 | 67.8 |

- A microVM cost about 6% on the cold build and 7% on the whole run; gVisor
  about 40%. All six runs produced the same output and passed every probe.
- That supports prototyping a VM backend further rather than rejecting it on
  assumed cost. It does not make one the default: two trials, and none of the
  candidates had airbag's per-file audit, `$HOME` branch, credential mediation,
  approvals or resume, so the security profiles are not equivalent.
- Before choosing a default: ten or more trials on target machines with real
  Go, Python, Node and browser tasks, an end-to-end budget agreed with pilot
  users, and no candidate that loses a required control.
- `/dev/kvm` was available on a hosted runner, which bears on the NixOS VM test
  matrix that [roadmap.md](roadmap.md) defers for lack of KVM in CI.

## Reusing AgentFS for the branch (PR #20)

Branch `research/filesystem-backends`; write-ups `docs/filesystem-backends.md`
and `docs/agentfs-diagnostics.md`, raw data `testdata/agentfs/`.

The question: could AgentFS (or a loopback FUSE filesystem) back airbag's
copy-on-write branch, and does it work on macOS without macFUSE? AgentFS v0.6.4
was mounted for real on Ubuntu 24.04 (FUSE) and macOS 15.7 (localhost NFSv3),
and a probe ran a copy-on-write workload and a real git commit on it.

| | Linux, FUSE | macOS, NFS | airbag on macOS (APFS clone) |
|---|---|---|---|
| copy-on-write, fsync, rename, links, mmap, flock | pass | pass | pass |
| write, chmod 0444, close, rename | pass | fail (EACCES) | pass |
| `git add`, commit, fsck | pass | fail at `git add` | pass |
| `agentfs exec` with an overlay base | fail (30 s pool timeout) | fail | n/a |

- AgentFS is a plausible optional storage backend, not a replacement for
  airbag's branch or its policy gate. airbag keeps its own backing files and
  SQLite audit; AgentFS stores file contents in SQLite too, so it would remove
  neither SQLite nor the FUSE boundary on Linux.
- The macOS failure matches airbag's own NFS probe (N3 in
  [macos.md](macos.md)): git cannot close a loose object over that NFS server.
  It backs the condition macos.md sets for an NFS overlay, and with it a `$HOME`
  branch on macOS: the server must keep handles valid and let git write.
- The `exec` timeout looks like an upstream connection-pool defect (by reading
  the source, not traced); the macOS cause is also inferred, not traced.
- Not tested: crash and power-loss durability, and policy equivalence.
- Found on the way: a deep `AIRBAG_HOME` can exceed macOS's Unix socket path
  limit (`bind: invalid argument`).
