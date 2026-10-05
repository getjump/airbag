# Runtime filesystem and audit measurements

Measured implementation: `1d43ea287ab1522063ac7cf5a17071513d0be055`.
Previous implementation: `182ddaf0c4f8849aa7d314674a5a473c795396a4`.
Fixed source built by both: `543fe189b85a0e85870ee9d92244eb2d89385280`.

[CI run](https://github.com/getjump/airbag/actions/runs/37233697480).
Production comparisons disable profiling. Each parallelism uses its own runner;
compare modes within one runner, not across p1/p2. CGO=0, offline modules,
buildvcs=false, empty Go cache for cold; OS/module caches remain warm. Compiler
scratch is private /tmp outside workspace/HOME FUSE. Each condition has two cold
and six unchanged/incremental samples. Phase times exclude startup, hashing and
final review; session profiles aggregate all seven builds plus their hashing.
These results cover this Go source/toolchain and runner, not all file workloads.

## Parallelism 1

Median seconds in order: empty Go cache / unchanged / one-package incremental.

- after/baseline: **23.4410 / 0.0992 / 0.6979 s**.
- after/exec: **24.3520 / 0.1075 / 0.7035 s**.
- before/fuse: **31.3834 / 1.2078 / 2.1782 s**.
- after/fuse: **30.3379 / 1.2449 / 2.2214 s**.
- before/both: **31.0185 / 1.2262 / 2.4451 s**.
- after/both: **30.1970 / 1.1885 / 2.1770 s**.
- after/fuse-buffered: **26.2606 / 0.6051 / 1.4646 s**.
- after/both-buffered: **26.2970 / 0.6111 / 1.4525 s**.

Durable FUSE is approximately unchanged relative to the previous implementation;
the small shifts are within the sample spread. Switching current FUSE to buffered
reduces cold time by 13.4%, unchanged by 51.4%, incremental by 34.1%. This mode
changes crash durability; it is not an equal-durability engine optimization.
Every FUSE condition retains 35,364 filesystem events per seven-build session;
combined modes also retain 484 exec events. Sealed data cache is off in these
runs and does not explain these gains.

[Raw p1 artifact](https://github.com/getjump/airbag/actions/runs/37233697480/artifacts/11315101970).

## Parallelism 2

Same columns: empty Go cache / unchanged / one-package incremental, median seconds.

- after/baseline: **22.5028 / 0.0913 / 0.7882 s**.
- after/exec: **23.6074 / 0.0994 / 0.8022 s**.
- before/fuse: **38.5608 / 1.9632 / 3.8056 s**.
- after/fuse: **34.9350 / 1.5388 / 3.9131 s**.
- before/both: **36.3872 / 1.7374 / 3.2724 s**.
- after/both: **33.2069 / 2.3210 / 3.9592 s**.
- after/fuse-buffered: **25.4499 / 0.5335 / 1.6124 s**.
- after/both-buffered: **25.9958 / 0.5288 / 1.5820 s**.
- profile/fuse: **44.7219 / 1.9543 / 3.1148 s**.
- profile/fuse-buffered: **26.1482 / 0.5872 / 1.5874 s**.
- diagnostic/plain-fuse: **24.1088 / 0.3389 / 1.3373 s**.
- diagnostic/policy-no-audit: **25.0077 / 0.5186 / 1.5622 s**.

Runner/toolchain: four vCPUs, Linux 6.17.0-1022-azure, **Go 1.27.1**,
Ubuntu 24.04. Both p1 and p2 use that Go version; these numbers are not directly
comparable to the earlier Go 1.24.13 run. p2 durable timings are especially noisy:
current FUSE unchanged spans 1.030–3.350 s and incremental 2.229–4.855 s;
combined unchanged spans 1.693–3.455 s, incremental 2.240–6.106 s. Do not infer
an equal-durability regression or improvement from the medians alone. p1 is more
stable and does not establish a meaningful durable-mode improvement either.

Current p2 FUSE buffered versus durable medians: cold 34.9350 → 25.4499 s,
unchanged 1.5388 → 0.5335 s, incremental 3.9131 → 1.6124 s. The large p2 spread
limits precise percentage claims; p1 independently supports the buffering gain.
Buffered unchanged remains about 5.84 times baseline, an additional 0.4422 s.
All production FUSE conditions retain approximately 35,364–35,365 filesystem
events per seven-build session; exec-enabled cases retain 484–485 exec events.
Counts vary by one between sessions; this alone is not evidence of lost audit.

## What the ablations establish

Instrumented plain FUSE unchanged is 0.3389 s, policy/RPC without audit 0.5186 s,
and profiled buffered 0.5872 s. Primary unprofiled buffered is 0.5335 s. The
baseline is 0.0913 s. This is consistent with separate costs for the FUSE data/
metadata path, synchronous RPC/CEL decisions, and durable audit. Instrumentation
and run variability prevent treating differences as an exact additive budget.
The ablations intentionally remove protections and are benchmark-only binaries,
not production options. They preserve secret notification durability.

Across two profiled seven-build durable FUSE sessions, 31,011/31,117 runtime
commits account for 46.132/31.676 s of controller commit wall time. This includes
SQLite execution, locking, fsync and checkpoint work; it does not identify each
component. Maximum observed commit is 0.488/0.346 s. Client RPC sums are
89.399/60.323 s and include overlapping callers, so they exceed some wall phases
and must not be added to commit/callback times.

Buffered sessions commit 35,364 events in **1,504/1,720 commits**, with 8.285/7.211 s
of background commit wall time. Controller queue-ack sums are only 0.096/0.104 s.
Peak outstanding events are 2,709/1,075, accounted bytes 883,516/344,846, with no
backpressure or persistence failures. There is no crash-loss measurement here;
clean-stop drain and secret durability are verified independently.

Durable sessions also see 61,856–63,733 LOOKUP callbacks versus 54,295–54,381 for
plain FUSE and about 56k for buffered. Expiry of the 100 ms metadata TTL during
longer waits is a plausible contributor, not an isolated TTL experiment. READ
callback totals exclude kernel backing-data transfer after ReadResultFd and do
not show the entire data-plane cost.

## Storage conclusion and artifacts

[Raw p2 JSONL and storage output](https://github.com/getjump/airbag/actions/runs/37233697480/artifacts/11314953071).
See [audit-storage.md](audit-storage.md) for equal-durability storage medians.
Single-event append+fsync does not beat SQLite on this runner. At batch 64,
append is faster, but buffering already puts build latency close to policy/RPC
without audit. These data justify keeping SQLite for this iteration and focusing
next measurements on FUSE/metadata and RPC before migrating the audit format.

