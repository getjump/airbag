# AgentFS Mac diagnostics after the mount comparison

This extends [the filesystem backend assessment](filesystem-backends.md).
Measured probe commit: `ddd2a2fc90e30f4a4d326ab75726b6d896a15cc1`.
Official AgentFS v0.6.4 binaries; macOS 15.7.9 ARM64 and Ubuntu 24.04.
[CI run 37257841009](https://github.com/getjump/airbag/actions/runs/37257841009).

Linux/FUSE passes the mounted COW, POSIX and normal Git workload. Mac/NFS
mounts successfully and preserves the base, but still fails normal Git and
the write/chmod-0444/close pattern. `exec` with an overlay base still reaches
the 30-second pool timeout on both platforms; explicit `mount --foreground`
is measured separately and never reported as a passing exec invocation.

Two additional diagnostics preserve the failing required verdict:

| Diagnostic | Linux | Mac |
| --- | --- | --- |
| fsync before chmod 0444, then close/rename/read | Pass | Pass |
| Real Git add/commit/fsck with core.fsync=loose-object and core.fsyncMethod=fsync | Pass | Fail at Git add |

Normal Mac Git reports `error when closing loose object file: Permission
denied`. With the fsync settings it reports `fsync error` on the temporary
object with `Permission denied`. Thus these settings **do not repair this
Git workflow**. A successful hand-written ordering workaround is insufficient
to claim arbitrary tool compatibility. The results support investigating
permission/writeback ordering in the NFS path, but do not isolate the exact
server/client syscall sequence or prove all NFS implementations fail.

Next steps for reuse are bounded: fix the upstream exec connection lifetime,
resolve and reproduce the Mac readonly/Git behavior, then measure real builds
under matched durability/cache settings and implement Airbag's admission
adapter. Do not disable permission checks to make the workload pass. Keep
Airbag's current backing files and policy gate for this iteration.

The Mac compatibility job intentionally remains failed for the observed
required operations. That is evidence against replacement readiness, not an
Airbag production regression. Audit counts after these mounted operations
are zero in the AgentFS tool-call table on both platforms, with no claim of
complete filesystem event telemetry. No crash/power-loss or policy-equivalence
test was performed.

Raw JSON and logs: `testdata/agentfs/2026-10-05-diagnostics/`.
[Linux artifact](https://github.com/getjump/airbag/actions/runs/37257841009/artifacts/11323521285)
and [Mac artifact](https://github.com/getjump/airbag/actions/runs/37257841009/artifacts/11323920373).
[Git configuration semantics](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corefsync).
