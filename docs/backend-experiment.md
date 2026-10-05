# Native, gVisor and microVM: hypotheses before a backend rewrite

This is an offline Linux experiment, not a production backend. The candidates
are native Airbag in strict/no-home mode, runsc systrap with no network, and a
Firecracker microVM with no network device. Only the native candidate runs
Airbag's session/import/control implementation. Full policy equivalence is
explicitly false in the result metadata.

## Hypotheses and decision rules

1. **A guest-native filesystem may offset microVM setup cost.** Measure
   fixture creation, per-session preparation, startup to a ready marker,
   cold/unchanged/incremental builds and complete execution separately. A
   faster build alone does not establish lower end-to-end cost.
2. **gVisor may be usable without KVM but cost more for small filesystem
   operations and process starts.** Test systrap with the same Go toolchain,
   source and fixed parallelism. Failures count as compatibility failures,
   not missing samples to remove from an average.
3. **A stronger execution boundary can preserve an offline coding workflow.**
   Build and execute the real Airbag program, run selected real unit tests,
   create/read/stat/rename/remove 2,048 files and start 32 child processes.
4. **Backend selection cannot substitute for semantic effect policy.** None
   of these bare candidates implements a JIT credential broker or an exact
   GitHub operation grant. The typed-effect work (#15/#17) remains separate.

Use two rotated trials as a feasibility check, not a statistically strong
ranking. Before choosing a default, rerun with at least ten trials on the
target machines and representative Go/Python/Node/browser/package tasks.
Predeclare the acceptable end-to-end budget with pilot users. Reject a
candidate that loses a required control even if it is faster.

The source snapshot is fixed at `b4231df2368c8c20a15912a86680fd366ba93fc2`.
Dependencies are vendored before timing. All candidates use the same supplied
Go toolchain, no downloads, `CGO_ENABLED=0`, `GOMAXPROCS=1`, and `-p=1`.
Cold means an empty per-session Go build cache, not a cold host page cache.
Three unchanged builds reuse that cache; incremental adds a package-level
variable to the real command source. Both the small-files and exec workloads
are synthetic diagnostics, labelled separately from the real build.

## What the boundary checks establish

A host-only benign file canary must be unreadable, direct connection to a
live host TCP listener must fail, and the original source tree must remain
unchanged. An unrestricted negative control must detect access to both
canaries. Native also checks its real workspace lower after the run.

These are regression probes for the configured paths and network, not proof
against kernel escapes, every filesystem alias, DNS/UDP, compromised guest
telemetry or unsafe exports. Results emitted by the guest are observations
of a trusted deterministic workload. They are not attestations. The VMM
has no guest network interface; no real service credentials are supplied.

The experiment does not implement per-file audit, HOME branching for
candidates, proxy credential mediation, API approvals, resource-budget
equivalence, terminal/resume or automatic watchdog/kill policy. Firecracker
uses its default seccomp but not its production jailer. Do not run hostile
code through this developer harness or expose it as an Airbag backend.

## Reproduce

`.github/workflows/backend-lab.yml` runs on this repository's experiment PRs
and manual dispatch. It pins gVisor 20260928.0, Firecracker 1.17.0 and a guest
kernel 6.1.155, with expected archive/kernel hashes. Raw versions, logs,
configuration, source digest and JSONL outcomes are uploaded even on failure.
Unavailable KVM is a distinct result and fails the comparison; it never
becomes a passing microVM sample or silently runs without virtualization.

For local execution, build `./cmd/airbag-runtimeprobe` with CGO disabled,
prepare a vendored source snapshot and invoke `python3 test/backend-lab.py
--help`. Use a fresh output directory outside HOME and `/tmp`, writable
user namespaces, runsc with its matching sidecar directory, and writable
`/dev/kvm` for Firecracker. Image downloads and initial Go/tool preparation
are outside session timing and are an additional deployment cost.

Primary implementation sources:
- [gVisor installation](https://gvisor.dev/docs/user_guide/install/)
- [gVisor filesystem](https://gvisor.dev/docs/user_guide/filesystem/)
- [Firecracker getting started](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/getting-started.md)
- [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/prod-host-setup.md)

## Product hypothesis: requires humans

Technical compatibility and benchmark wins do not establish market fit.
The pilot hypothesis is that teams running coding agents unattended value
reviewable changes and precisely scoped external effects enough to return
to Airbag repeatedly. Follow [the existing evaluation](evaluation.md) with
real tasks and developers; no interviews or adoption evidence are claimed.

Record setup effort, completed tasks, interruptions, human review time,
meaningful blocked effects, environment repairs, repeats per week, and why
people leave. Compare built-in sandbox + worktree as well as competing
products. Ask for a paid pilot after successful repeated use, not an opinion
about whether agent security is important. The initial threshold remains
five of ten developers using it several times weekly after two weeks; it is
an experiment choice, not a definition of PMF. No user outreach is automated.

## Measured results

Pending the first CI run. Do not infer runtime performance from vendor claims.
