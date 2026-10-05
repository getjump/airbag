# Filesystem reuse: AgentFS, loopback FUSE and macOS

Assessment date: 2026-10-05. AgentFS is a plausible optional COW/storage
backend, not a drop-in replacement for Airbag's runtime policy gate. Keep
the existing native backing files and SQLite audit for this iteration;
prototype an adapter only after the compatibility, admission and durability
tests below pass. A mount working on macOS does not establish policy parity.

Airbag main at `b4231df2368c8c20a15912a86680fd366ba93fc2` uses Linux
overlayfs and macOS workspace cloning. The runtime filesystem gate discussed
here is in [PR #9](https://github.com/getjump/airbag/pull/9), inspected at
`82f4f2f2a599c5efe6e8e19218cb810c8c179871`; it is not shipped in main.
It mounts policy FUSE **above the completed workspace/HOME view**, gates
entry points using the controller, and records attempts according to the
selected audit durability. It does not promise one callback per syscall,
complete mmap telemetry or every byte transfer. Backing access is fd-relative;
secret reads also trigger network taint handling. These responsibilities
must survive any change of storage implementation.

## What each component supplies

| Candidate | Storage/view | Policy integration | macOS path |
| --- | --- | --- | --- |
| Airbag native + policyfs | Native file data, overlay COW, separate SQLite audit | Our controller admission, secret notification and audit | Main uses Seatbelt + workspace clone; Linux policyfs has no Mac port |
| AgentFS | SQLite-compatible file data/metadata, overlay and whiteouts, explicit tool-call table | Needs an Airbag admission/audit adapter | Built-in local NFS mount; no macFUSE required |
| agentsh filesystem | Loopback FUSE integrated with its sessions | Existing policy, approval, event/trash hooks; tightly coupled internals | Separate platform security mechanisms; Linux FUSE is not the Mac backend |
| unionfs-fuse | COW union view and whiteouts | No Airbag semantic gate or audit integration | Project documents MacFUSE support; needs our compatibility checks |
| bindfs | Permission/ownership remapping over an existing tree | Not a COW or semantic effect-policy engine | fuse-t support is best effort; MacFUSE not properly supported upstream |
| macFUSE / FSKit | Mount framework, not a complete COW store | We still implement backing view and gates | macFUSE supports a userspace FSKit backend for supported filesystems |

AgentFS source examined at main commit
`0a014ebd4918615baff589ed17486e557e7c6a23` and CLI release v0.6.4
(`3a5ed2b88e5d5a5f9b2c7fe02d012b50fd19e3c0`). The release is pinned in
the probe, with archive hashes. agentsh source examined at
`0ce9939b6ccead8b21b9ce16783b287d18012777`. Other entries describe upstream
scope, not tested speed or an equivalent security guarantee.

## AgentFS: benefits and integration costs

The useful reusable parts are its filesystem SDK/overlay, a portable database
representation, whiteouts and mounted access for ordinary CLI programs.
This can reduce new COW/storage work, especially on Mac. Its Go SDK is present
in the inspected main source, but mounting uses the Rust CLI; do not assume
a Go SDK import supplies its mounted runtime or policy callbacks.

The current filesystem tables describe file state. `tool_calls` records
explicitly instrumented tool calls; that schema alone is not a complete
per-operation filesystem audit. A real v0.6.4 CLI `fs write` followed by
`fs cat` returned the expected bytes and left that table empty. The probe
also counts it after mounted operations, with the scope labelled explicitly.
This is an observation of these paths, not a claim that AgentFS has no
logging or that an SDK caller cannot add instrumentation.

The inspected FUSE adapter uses a very long metadata TTL and permits kernel
data caching. Its filesystem SDK selects `synchronous=OFF` for ordinary
operations and temporarily uses `FULL` at explicit fsync points. These are
different contracts from Airbag's durable audit-before-admission mode.
Compare buffered to buffered, durable to durable, and specify what an ack
means. Do not attribute all speed differences to the database engine or
claim fsync is broken from source inspection alone.

AgentFS still uses a SQLite-compatible database, now for **file contents as
well as metadata**. Adopting it would not remove either the SQLite dependency
or the Linux FUSE boundary. Airbag's current data files are native; SQLite
stores audit/session state. It is a change of data path, not just replacing
our audit database with a faster implementation.

## Will it work on Mac?

Upstream supports mounted access through NFS over localhost and the built-in
`mount_nfs`. Its implementation requests NFSv3/TCP and `locallocks`. This
avoids installing macFUSE for that path. The included CI checks the actual
mount on Apple Silicon macOS 15, rather than treating an SDK read/write as
proof of mounted compatibility. Intel, other macOS versions and real builds
remain separate coverage requirements.

NFSv3 requests do not provide the originating process PID or a FUSE-style
OPEN callback, and client caching can serve access without a fresh RPC.
Therefore we infer that a session-wide storage adapter is more straightforward
than preserving our per-process open admission/audit contract. This is a
design inference to test, not a measured bypass in AgentFS. A policy wrapper
around SDK methods does not intercept cached client accesses automatically.

Do not adopt AgentFS's whole sandbox as part of a storage experiment: its
Seatbelt/host passthrough settings must be reviewed against Airbag's HOME,
secret and proxy controls independently. `agentfs exec` mounts and executes;
the probe deliberately uses it without claiming whole-host isolation.

Also, "FUSE on Mac always needs a kernel extension" is outdated. macFUSE has
an FSKit userspace backend; its current homepage describes supported
filesystems on macOS 26. That does not make our Linux go-fuse code portable
without a mount/protocol adapter, and does not prove the admission, PID,
cache or performance properties we need.

## Checks before adopting a backend

1. Run the included COW/POSIX/Git probe on Linux and macOS. Missing mount
   capability and failed operations remain failures, with logs retained.
2. Run the same real Go, Node and Python cold/unchanged/incremental builds,
   same toolchain, parallelism, source and cache/durability profile. Measure
   staging, mount, workload and export separately. Do not compare our earlier
   benchmark to an upstream advertised result with different conditions.
3. Implement admission above the final merged view. Test an existing upper
   file, copied-up file, rename, hardlink/symlink aliases, open handles after
   revocation, inherited descriptors, mmap, and client cache behavior. Define
   supported controls and explicitly reject unavailable ones.
4. Verify audit ordering and crash recovery: kill the controller/storage
   process at each boundary; distinguish operation attempt, admission and
   success. Check policy and secret notifications under concurrent fsync.
5. Verify diff/export, deleted files, permissions, links, resume, disk-full
   behavior and shutdown/drain. Keep backing DB/base paths inaccessible to
   the agent, and review selected component licensing before vendoring.

The probe's `fsync` is a compatibility check, not a power-loss experiment;
its `flock` is a local round trip, not cross-client locking validation.
Its phase durations are diagnostics, not representative build measurements.
No automatic replacement of Airbag storage or policy is implemented here.

## Reproduce and evidence

`.github/workflows/agentfs-probe.yml` downloads pinned v0.6.4 binaries and
runs `test/agentfs-probe.py` on Ubuntu/FUSE and macOS/NFS. It checks an actual
mount, COW base preservation, file fsync/stat/rename/read, aliases, mmap
reads, local flock, the 0444 loose-object pattern, and a real local Git
commit/fsck. `--cli-only` is explicitly labelled and never reports a mount.

Measured probe commit: `7917a87194c6a25edbb505f42a3f74d9ec1f1f81`.
[CI run 37257296082](https://github.com/getjump/airbag/actions/runs/37257296082)
tested official v0.6.4 release binaries on both platforms:

| Check | Linux 6.17 / FUSE | macOS 15.7.9 ARM64 / NFS |
| --- | --- | --- |
| Real foreground mount | Pass | Pass |
| COW write/delete and base unchanged | Pass | Pass |
| Create/fsync/stat/rename/read | Pass | Pass |
| Hardlinks, symlinks, mmap read, local flock | Pass | Pass |
| Write, chmod 0444, close, rename | Pass | Fail: Permission denied |
| Actual Git add/commit/fsck | Pass | Fail at git add |
| `exec` with an overlay base | Fail: pool timeout | Fail: pool timeout |
| `tool_calls` after our mounted operations | 0 rows | 0 rows |

This establishes actual Mac mounting, but not sufficient compatibility for
our coding workflow. The macOS job stays red for the real workload failures;
the explicit foreground mount is not reported as a successful `exec`.
Raw outputs and logs are committed in `testdata/agentfs/2026-10-05/`;
[Linux artifact](https://github.com/getjump/airbag/actions/runs/37257296082/artifacts/11322649641)
and [Mac artifact](https://github.com/getjump/airbag/actions/runs/37257296082/artifacts/11323256515)
preserve the independent results. Neither platform populated the tool-call
table in these paths; no complete filesystem-audit claim follows from that.

Source analysis explains the `exec` failure: it keeps a pooled connection
alive while `overlay.load()` asks for another; the inspected pool permits
one connection and has a 30-second timeout. The explicit `mount` path scopes
that first connection separately. Both official binaries produced the same
timeout. This is an upstream integration defect, not missing FUSE/NFS support.

The readonly/Git failure is consistent with delayed NFS writeback encountering
the changed permissions. This remains a hypothesis: the updated probe adds
a **non-gating diagnostic** with fsync before chmod, and captures Git stderr.
A passing workaround must not convert a failing real Git task into a pass.
The upstream [Mac Rust build report](https://github.com/tursodatabase/agentfs/issues/260)
also motivates real build coverage, but is a different report, not our
reproduction or evidence that all current versions fail.

For adoption: fix/retest the upstream exec path and Mac readonly/Git behavior,
then measure real builds and build the admission adapter. Reusing Linux
storage is plausible; replacing our policy gate wholesale is not established.
Keep the current Airbag filesystem implementation while these gaps remain.

Primary sources:

- [AgentFS manual at the inspected release](https://github.com/tursodatabase/agentfs/blob/v0.6.4/MANUAL.md)
- [AgentFS specification](https://github.com/tursodatabase/agentfs/blob/v0.6.4/SPEC.md)
- [AgentFS FUSE adapter](https://github.com/tursodatabase/agentfs/blob/v0.6.4/cli/src/fuse.rs)
- [AgentFS filesystem durability](https://github.com/tursodatabase/agentfs/blob/v0.6.4/sdk/rust/src/filesystem/agentfs.rs)
- [AgentFS NFS mount implementation](https://github.com/tursodatabase/agentfs/blob/v0.6.4/cli/src/mount/nfs.rs)
- [agentsh](https://github.com/canyonroad/agentsh)
- [unionfs-fuse](https://github.com/rpodgorny/unionfs-fuse)
- [bindfs support scope](https://bindfs.org/)
- [macFUSE backend documentation](https://github.com/macfuse/macfuse/wiki/FUSE-Backends)
- [macFUSE current platform support](https://macfuse.github.io/)
