# Optional execution boundaries

Native remains the default. This experimental adapter adds Linux gVisor
(application kernel) and Linux amd64 Firecracker (KVM microVM) execution to
Airbag's existing host policy, credential, audit, outbox, review and apply flow.
The providers never fall back to native. A recorded isolation requirement and
provider configuration survive resume.

This is an **isolated workspace profile**, not parity with native's entire
machine branch. It requires `--no-home`: the image supplies tools, workspace
writes go to a private copy, HOME is empty and private. Host HOME, agent login
passthroughs and the host toolchain are not mounted. Configure an agent through
the trusted image and explicitly permitted environment instead.

```sh
airbag capabilities --backend=gvisor --json
airbag run --backend=gvisor --require-isolation=application-kernel --no-home \
  --runtime-bin=/opt/gvisor/runsc --runtime-rootfs=/opt/airbag/rootfs -- /usr/bin/agent

airbag run --backend=microvm --require-isolation=virtual-machine --no-home \
  --runtime-bin=/opt/firecracker/firecracker --runtime-kernel=/opt/firecracker/vmlinux \
  --runtime-rootfs=/opt/airbag/rootfs -- /usr/bin/agent
```

Use dedicated, trusted rootfs directories and a static Linux Airbag executable
(`CGO_ENABLED=0`). Runtime/rootfs/kernel artifacts are supplied by the operator;
there is no automatic download or image provenance claim. Keep runsc's matching
`gvisor-bin` sidecars next to it. Nonroot gVisor runs use runsc's rootless mode and
need unprivileged user namespaces. Firecracker needs writable `/dev/kvm`,
`mkfs.ext4`, and a kernel with built-in ext4, devtmpfs and virtio-vsock support.
Rootfs and sessions must be separate from the workspace. A workspace reached
through a symlink is checked and copied as the directory it names. Commands must
exist inside the image; host executable paths are not imported.

## Shared contract

The same host `policy.Gate`, credential resolver, proxy/mirror, effect log,
control server and outbox serve native and optional execution. The agent never
receives the effect database or the proxy CA private key. Credential substitution
and response masking stay outside the boundary. Semantic command policies are
still enforced by shims and hooks, with the existing limitations of command
prediction; this does not claim syscall process audit.

For gVisor, `--network=none` provides only sandbox loopback. The image receives
exactly two host Unix sockets: the proxy and policy control channel. The helper
bridges sandbox HTTP proxy traffic to its scoped socket. Rootfs is readonly;
workspace and HOME/tmp are the only mutable views. The rootless guest uses virtual UID zero (mapped to the host user) so private
files retain access permissions. This grants no host root identity. Agent capabilities are empty,
no_new_privs is enabled and user namespace creation is denied: the spec's seccomp
rules refuse unshare, setns and clone with CLONE_NEWUSER (runsc loads them only
with `--oci-seccomp`, always with EPERM), and a filter the guest adds refuses
clone3 with ENOSYS, so glibc falls back to clone.

Firecracker has no NIC. Guest-to-host vsock ports expose proxy, control and a
bounded result export only. The guest init mounts private workspace storage,
drops agent UID/capabilities, prevents user namespace creation and runs the
agent with no_new_privs. No host HOME or generic host execution service is
exposed. The host never mounts a guest-written ext4 image. It validates a tar
export into a fresh confined directory, rejecting traversal, symlink parents,
devices, hardlinks, duplicates and excessive sizes before publishing the branch.
Guest exit status and exported files are **untrusted output**, not attestation.
Existing review/apply guards decide whether and where output reaches real files.

In both runtimes the agent gets native's filter (`--strict` adds the strict
one) and the guest's clone3 filter. Just before the exec, under those filters,
the guest checks that clone3 is refused and that a child cannot start in a new
user namespace; otherwise it stops the run.

## Explicitly unsupported

Preflight rejects workspace secret files (the native secret-read FUSE/taint
contract is not integrated), explicit hide rules, HOME branching, TCP forwards
and Nix daemon access. There is no runtime filesystem or exec-notify audit from
the separate experimental policy PR. JIT token issuance/TTL, generic automatic
kill budgets and Firecracker jailer integration remain separate work.

Preflight also checks static Airbag, socket path length and the microVM image tool.
Agent managed hook configuration is installed into the readonly guest image,
preserving existing Codex requirements.

This adapter supports noninteractive commands and rejects terminal stdin; PTY/resize/job control are not
provided. Each microVM run starts fresh HOME/tmp and exports only workspace;
background processes are killed before export. On interruption/crash without
export, the prior branch is retained and the run fails; a run that fails
after the session exists still records it stopped, so it can be reviewed,
resumed or discarded. Input files are copied, not reflinked in the current workspace copy path; the tar path does not preserve
hardlink identity or directory modes. Fixed microVM limits are 1 vCPU, 2 GiB RAM,
2 GiB rootfs and 10 GiB workspace disk; export is bounded to 8 GiB/200k entries.

Both providers are Linux options. Native Mac remains APFS clone + Seatbelt;
Firecracker cannot run directly on macOS's hypervisor API. A Mac VM provider is
not implied by selecting microvm.

## Validation

`.github/workflows/runtime-options.yml` runs the real CLI with pinned runsc,
Firecracker and kernel versions. Benign fixtures check inaccessible host files,
denied direct egress, a permitted credential-bearing HTTPS request with masking,
a host policy denial on an allowlisted host, deferred outbox commands, offline Go
compilation, review, resume without isolation downgrade, and explicit file apply.
Raw timings/logs are artifacts, including failures. Timings measure this small
integration fixture; they are not comparable to the earlier vendored Airbag
build experiment. Unit tests exercise hostile exports and unsupported profiles;
regular CI continues native end-to-end, race, lint and Darwin cross-build checks.

## First passing real-provider run

Measured adapter commit: `e8cf0bb667f65b844dee18632e35f85a1f1c4db4`.
[CI run 37261063714](https://github.com/getjump/airbag/actions/runs/37261063714),
[raw artifact 11325136010](https://github.com/getjump/airbag/actions/runs/37261063714/artifacts/11325136010).
A subsequent harness adds host negative controls for the exact direct-egress
address, host-file readability/writeability and user namespace availability.
These controls must succeed outside the sandbox before a guest denial counts.
That run's `user_namespace_denied` called unshare(CLONE_NEWUSER) from Go,
which fails with EINVAL in any multithreaded process, and runsc ignored the
spec's seccomp rules without `--oci-seccomp`: the gVisor guest could create
user namespaces, `--strict` included. The check now starts a child in a new
user namespace, `clone3_unavailable` is added, and the run below predates both.
Both providers pass all nine guest checks, host-observed credential use (two
requests each), unchanged source before apply, resume and explicit file apply.
The result is one trial per backend on one runner:

| Backend | Cold fixture build | Whole initial Airbag run |
| --- | ---: | ---: |
| gVisor | 8.078 s | 9.401 s |
| Firecracker | 5.885 s | 10.141 s |

This compiles a single Go program and its standard library dependencies with a
fresh private cache, `GOMAXPROCS=1`, `-p=1`, and networking disabled for Go.
Whole-run time includes CLI setup, workspace/rootfs staging, policy/credential
checks, execution, result export and shutdown. Firecracker is 1 vCPU/2 GiB; there
is no matching native trial here. These numbers validate an operating adapter,
not a performance ranking or a substitute for the full vendored Airbag build
experiment in #19. Later code removes mkfs's generated `lost+found` before the
agent starts, preserving a recovery directory already present in source.
Raw JSON and versions are in `testdata/runtime-options/2026-10-05/`.
