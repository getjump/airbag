# Runtime policy on a reviewable branch

Airbag's main workflow remains: run an agent in a branch of the workspace and
HOME, review the result and outbox, then apply, apply to a git branch, or discard.
On Linux, two opt-in flags add policy checks while that branch is running:

```sh
airbag run --fs-policy --exec-policy -- make test
airbag log --json
airbag review --json
```

The flags persist across `run --session ID`. Filesystem policy needs writable
`/dev/fuse` and `openat2` (Linux 5.6+). Exec policy needs seccomp user notification
with CONTINUE support (Linux 5.5+) and `process_vm_readv` permissions in the
supervisor. Currently only native Linux amd64 and arm64 exec ABIs are supported;
compat and x32 syscall ABIs receive ENOSYS. macOS rejects both flags.

If an enabled backend cannot start, airbag refuses to start the agent. FUSE is
not silently replaced by shell predictions. In particular `AIRBAG_NO_FUSE=1`
cannot be combined with `--fs-policy`.

## Filesystem boundary

The mount order is the boundary:

1. Build overlayfs workspace and HOME branches, pass-through mounts, hidden
   paths, and read-only secret mounts.
2. Capture directory descriptors of **both completed views**.
3. Mount policy FUSE over HOME, then over the workspace, before starting agents.

FUSE is above the merged view, never just below overlayfs's lower layer. A file
created or copied into the writable upper is subject to the same checks. With
`--no-home`, HOME stays read-only but its reads still go through policy FUSE.
Agent state that normally passes through HOME is checked too.

The backing descriptors are CLOEXEC and live only in PID 1. That supervisor is
non-dumpable so the agent cannot reopen them through `/proc/1/fd` or ptrace. All
backing directory traversal uses `openat2` with BENEATH, NO_SYMLINKS and
NO_MAGICLINKS; the final component is opened with NOFOLLOW. Mount crossings are
allowed inside the already prepared view, so hidden paths and secret mounts
keep their behavior. A substituted backing symlink cannot redirect the server
outside the captured view.

| Entry point | Effects checked before forwarding |
|---|---|
| Open for reading, directory listing, readlink | `fs.read` |
| Open for writing/truncating/creating | `fs.write` |
| Create, mkdir, symlink, hardlink, FIFO/socket creation | `fs.write`; hardlink source also `fs.read` and `fs.write` |
| Unlink, rmdir | `fs.delete` |
| Rename | source `fs.delete`, destination `fs.write` and `fs.delete`; exchange also source `fs.write` |
| Setattr: truncate, chmod, chown, timestamps | `fs.write`; executable chmod/create also `fs.exec_bit` |

Rename conservatively checks destination deletion even when no destination
exists. Device node creation is refused. Rules address the operation's path,
not every descendant of a renamed directory. They are path policies, not labels
on all aliases of a file. Hardlink aliases get distinct FUSE inode identities to
keep their policy paths distinct; applications comparing hardlinks by inode
number may therefore behave differently.

Read/write access is authorized at open. Reads from an authorized descriptor,
page-cache hits, mmap, and subsequent writes through that descriptor are not
individual audited byte operations or a descriptor-revocation mechanism. In
particular a session-label change does not revoke previously authorized file
handles. FUSE passthrough is deliberately disabled. POSIX/flock locks, fsync,
fallocate and seek are forwarded on authorized handles. Xattrs and
copy_file_range are currently unsupported; tools need their usual fallbacks.
The rest of the host remains governed by its existing read-only mounts; private
scratch files in `/tmp` are outside these two filesystem policy views.

Secret taint still happens before bytes are delivered. The outer filesystem
matches the **opened backing inode** to the secret mounts and reports the
original caller PID/executable. It cannot mistake all reads for PID 1's own
reads or lose taint after a rename or hardlink alias.

## Process attempts

A trusted helper installs a seccomp USER_NOTIF filter immediately before
executing the agent. Its listener is transferred to PID 1 on a private startup
socket. The filter is inherited by descendant threads and processes, so
`execve` and `execveat` from make, Python and package scripts reach the same
policy gate as direct executions. PID 1 itself is not filtered.

The controller snapshots the actual executable pathname and argv from tracee
memory, resolves normal aliases in the caller's root, and checks `proc.exec`.
`execveat` handles directory descriptors and AT_EMPTY_PATH (including fexecve).
Arguments are bounded to 256 entries, 4 KiB per string and 64 KiB total. An
unreadable or over-limit invocation is logged as a denied `proc.exec.invalid`.
Notification IDs are validated before inspection and again before responding.

**This is an attempted-invocation policy, not immutable executable identity
 enforcement.** Seccomp CONTINUE lets the kernel reread the tracee's path and
argv. A second tracee thread can change them after inspection. Path contents,
symlinks and executable files can also change. The notification does not prove
exec succeeded, and kernel script-interpreter loading is not a separate exec
notification. Protect sensitive data with the filesystem and network boundaries;
do not use the argv snapshot as a security boundary against adversarial races.
No ptrace, executable hashing, signals policy or eBPF backend is added here.

## Policy and audit

```yaml
rules:
  - name: keep-lockfile
    when: effect.source == "fuse" && effect.target.endsWith("/package-lock.json") && effect.kind in ["fs.write", "fs.delete"]
    verdict: deny
  - name: approve-release-script
    when: effect.source == "seccomp" && effect.kind == "proc.exec" && command.argv.exists(a, a == "release.py")
    verdict: ask
```

Allow/deny/ask use the existing CEL gate. Ask returns EACCES, creates an
`airbag approve a-N` request, and requires a retry after approval; there is no
indefinitely paused syscall. Runtime approvals are scoped to source, effect,
operation detail and (for exec) argv. Approving one argument vector does not
approve different arguments to the same executable.

The private runtime socketpair is inherited by PID 1, not mounted into the
agent view. The agent-facing shim/control socket cannot forge runtime events.
Checks for one operation use one RPC and transaction. Independent in-flight
operations can share a commit without a fixed batching delay. The host commits
every evaluated decision to the append-only SQLite log (WAL, synchronous=FULL)
before releasing any operation in that commit group. Transport timeout/loss and audit commit failures deny access.
Audit records have source, PID, target, detail, and exec argv; they contain
attempts/entry-point decisions, not proof an operation completed successfully.
The ordinary log continues to read old sessions. `log --json` exposes context;
review summarizes runtime counts and preserves context for blocked operations.
Argv is audit data and may contain sensitive arguments; avoid putting secrets
on a command line.

## Compatibility and build cost

These backends remain opt-in until measured on representative toolchains.
`test/runtime-policy-e2e.sh` checks Python file mutations, overlay upper writes
and resume, make children, execveat, mmap, SQLite, locks, git branch isolation,
symlinks, hardlinks, sockets, protected HOME, supervisor descriptors and taint.
CI runs it on Ubuntu 24.04 alongside all existing E2E tests.

`sh test/runtime-policy-bench.sh` reports median wall times for a small C build
and a Python filesystem workload with the original sandbox, file policy, exec
policy, and both flags. CI records those measurements as a diagnostic, not a
performance guarantee or a fixed pass/fail threshold. The filesystem uses a
100 ms positive metadata/name cache, no negative cache and no cached policy
verdicts. Mutations are handled through go-fuse's normal inode updates; backing
changes made outside FUSE can remain visible with stale metadata for up to that
TTL. Open and mutation callbacks still check policy, even on a cached inode.
Directory listings stream getdents entries without an eager stat per child.
Rename moves a tree of stable path identities instead of scanning all known
inodes; successful deletion releases that identity subtree.

`test/runtime-build-bench.py` measures real builds of Airbag, with a fixed source
snapshot and pre/post-optimization binaries paired on the same runner. CI runs
`go build -p 1` and `-p 2` independently, two trials per condition, with three
unchanged and three incremental builds after each empty-cache build. Modes are
the original sandbox, exec only, FUSE only, and both; pre-optimization FUSE/both
are also measured. Incremental changes affect one package in `cmd/airbag`.
Module downloads happen beforehand, network fetching is disabled, CGO is off,
and VCS stamping is disabled consistently. Cold means empty Go build cache,
not empty OS page cache; compiler temporary files use the private `/tmp`. Phase
wall times exclude mount/setup and the final review scan; session wall and CPU
times include those costs. JSONL artifacts preserve every sample and audit
counts. These results describe this Go project and runner, not npm installs or
large C++ builds. Durable audit and synchronous CEL checks still add latency;
measure your actual project before changing the default.

Networking continues to use the existing isolated network namespace and forced
proxy. There is no direct egress interface to monitor with an additional eBPF
backend. LLM request-content DLP is a separate future capability, not part of
these file/process controls.
