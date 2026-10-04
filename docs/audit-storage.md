# Audit storage: engine choice and durability

Research date: 2026-10-04. Production baseline: `182ddaf`,
`modernc.org/sqlite v1.34.5` embedding SQLite 3.46.0. This document separates
storage-engine CPU cost from disk durability and from the FUSE/RPC/policy path.

## Decision

Keep SQLite for the first runtime-performance iteration. Introduce an explicit
buffered runtime-audit mode while preserving the durable mode. Changing engines
does not remove the disk barrier required by acknowledgement-after-sync.

There is a measurable CPU opportunity in our SQL schema and driver, so this is
not a claim that SQLite is free. Measure it on a real disk before deciding
whether a dedicated append journal justifies its recovery and compatibility
work. The diagnostic below supplies that comparison without a new production
dependency.

The strongest alternative for this particular workload is an ordered append
journal as the authoritative record, with SQLite as a derived review index. It
is a different architecture, not a drop-in database replacement. bbolt and LSM
stores remain candidates only if their measured advantage and additional KV
requirements justify the migration.

## What the current path pays for

`effects.Log.AddBatchChecked` uses prepared statements, one connection and one
transaction per admitted group. The schema adds an event row, normally a second
context row, an index on kind, and the AUTOINCREMENT bookkeeping. Runtime
context serialization is in the measured path. The RPC caller waits for commit.

SQLite WAL with `synchronous=FULL` synchronizes its WAL on commit. Switching to
NORMAL removes that barrier from most transactions and changes power-loss
durability; it is not a fair engine-speed comparison. The default automatic
checkpoint threshold is 1000 pages and a commit that crosses it can also do
checkpoint work. Disabling checkpointing indefinitely creates an unbounded-WAL
problem. See [SQLite WAL](https://sqlite.org/wal.html).

The group must already exist to amortize the barrier. Sequential operations
that wait for the preceding operation's acknowledgement do not naturally form
64-event groups. A buffered queue can accumulate them because its admission
acknowledgement has a different durability contract.

Low-risk schema experiments should precede an engine migration:

- Remove AUTOINCREMENT from newly created logs if never reusing a deleted id is
  unnecessary. Our append-only tables prohibit deleting events; INTEGER PRIMARY
  KEY still allocates row ids. The extra bookkeeping is documented in
  [SQLite AUTOINCREMENT](https://sqlite.org/autoinc.html).
- Store context columns in the event row to avoid the second INSERT and review
  join. This needs compatibility with existing logs.
- Measure the kind index's write cost against actual review queries before
  deferring or removing it. The SQL query examples also use it.
- Profile modernc's interpreter/driver work before considering a native-C
  driver. A cgo switch affects static builds and cross-compilation, and must
  compare the same SQLite version, schema, transaction size and sync contract.

None of those changes is implemented by this research benchmark.

## Alternatives under the same contract

**bbolt**, reference version v1.5.0, supplies a small pure-Go transactional
B+tree and ordered cursors. It could store sequence-keyed JSON and secondary
indexes, but the SQL/review schema would have to be rebuilt. Its documented
commit writes dirty pages and syncs them, then writes a new metadata page and
syncs again. `DB.Batch` combines concurrent calls; it is not a solution for a
single sequence of waiting callers. `NoSync` weakens the contract. There is no
measured bbolt win here. Source: [bbolt package documentation](https://pkg.go.dev/go.etcd.io/bbolt@v1.5.0).

**Pebble**, reference version v2.1.7, is a RocksDB-inspired LSM KV store with
ordered keys, atomic batches and WAL sync options. Durable per-operation writes
require sync. It adds memtables, SSTables, compaction, cache tuning and a KV
review/index migration. These can be worthwhile for a large, long-lived KV
workload; their benefit for a short session's append-only event log is
unmeasured. Source: [Pebble package documentation](https://pkg.go.dev/github.com/cockroachdb/pebble/v2@v2.1.7).

**Badger**, reference version v4.9.6, combines an LSM tree with a value log and
supports transactions. Its documented `SyncWrites` default is false; comparing
that default to SQLite FULL would conflate durability with engine performance.
A comparable experiment must explicitly enable synchronous writes. It also
requires a KV query/index migration and additional lifecycle/compaction work.
Source: [Badger package documentation](https://pkg.go.dev/github.com/dgraph-io/badger/v4@v4.9.6).

**A custom append journal** can store each admitted group as one sequential
frame and perform one sync before acknowledgement. This avoids SQL execution,
index updates and page rewriting. It cannot remove the sync wait for an
isolated durable operation. Making it authoritative requires a versioned
format, sequence numbers, commit boundaries, torn-tail recovery, bounded record
lengths, corruption detection, migration, concurrent-reader behavior, and safe
rotation. A derived SQLite index needs an explicit last-indexed sequence and
replay from the authoritative journal after crashes. CRC detects accidental
damage; it does not provide tamper evidence or an append-only security boundary.

The diagnostic journal implements only full-file writing/reopening and CRC
verification. It is deliberately not available as a production backend.

## Reproducible diagnostic

Run from the repository root:

```sh
go test ./internal/effects -run '^$' -bench '^BenchmarkAuditStorage$' \
  -benchtime=8192x -count=3 -timeout=10m
```

`internal/effects/storage_bench_test.go` compares:

- `sqlite-audit`: the actual production writer, FULL WAL, existing prepared
  statements/schema, event and runtime-context rows.
- `sqlite-flat`: diagnostic FULL WAL table containing ordered complete JSON
  events, no secondary index/context table/AUTOINCREMENT. It isolates a possible
  SQL/schema floor but omits production query fields and append-only triggers.
- `append-fsync`: one checksummed, sequence-numbered JSON frame per group,
  `File.Sync` before the group returns.

Every variant receives identical deterministic events, including runtime
context and occasional exec argv/predictions. Each repeat uses a fresh store,
256 warmup events and 8192 measured events. Setup and final close/read are outside
the timer. New journal creation and its directory are synced before measurement.
The SQLite schema creation is also outside the timer; its normal checkpointing
remains enabled. All records are reopened and compared for complete payload and
order after every repeat.

Both group sizes, 1 and 64, acknowledge after synchronous commit. `ns/op` and
allocations are per **event**, while `p50/p95/p99-ns/batch` are synchronous group
latency. The preformed batch experiment excludes queue-formation wait and
therefore does not establish a latency gain for sequential intercepted calls.
`live-B/event` is the total live file length divided by all measured and warmup
events, including SQLite's currently allocated WAL/SHM. It is not bytes written
to the device, final file size, or write amplification.

The benchmark prints Go/SQLite version, CPU count, GOMAXPROCS and the backing
filesystem's volatile option. It is single-writer, with no concurrent review,
FUSE, RPC, CEL or sandbox startup. Reopen verification is not a power-failure
test. CPU/noise and checkpoint tails should be examined alongside the median.

## Local CPU diagnostic, not durable-disk results

Environment: Linux 6.18.44, linux/amd64, AMD EPYC 9V74, 9 available CPUs,
Go 1.24.7, GOMAXPROCS=9, SQLite 3.46.0. `/workspace` and `/tmp` are on an overlay
mounted with **`fsync=volatile`**. Sync calls therefore do not establish normal
disk durability or measure its cost. These numbers must not be presented as a
speedup for a durable audit backend on users' disks.
The kernel documents `fsync=volatile` as the volatile-mount alias, which omits
syncs to the upper filesystem: [OverlayFS documentation](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html#volatile-mount).

Three-run median time per event:

- Production SQLite: **57.709 us** at group 1; **20.118 us** at group 64.
- Flat SQLite: **26.599 us** at group 1; **8.051 us** at group 64.
- Append journal: **2.358 us** at group 1; **0.8772 us** at group 64.

The three individual `ns/op` samples were:

```text
backend        group  samples (ns/event)
sqlite-audit       1  55407, 59074, 57709
sqlite-audit      64  20118, 18963, 21350
sqlite-flat        1  28347, 23821, 26599
sqlite-flat       64   8051,  8149,  7991
append-fsync       1   2761,  2344,  2358
append-fsync      64   1353, 846.4, 877.2
```

Allocations per event at groups 1/64: production SQLite 44/29, flat SQLite 22/11,
append 4/1. The preliminary result establishes material schema/driver/OS work
even when disk sync cost is absent. It does not isolate exactly how much of that
is AUTOINCREMENT, context table, kind index, database/sql, or modernc.

CI should repeat the same command on an ordinary disk-backed filesystem,
preserve the complete output and record the runner/mount details. A backend
decision must use those equal-durability results, plus full runtime/build
profiles. Storage-only percentages do not predict whole-build speedups.

## SQLite version maintenance

The current embedded 3.46.0 predates the WAL-reset race fix. SQLite documents
that the race needs multiple connections attempting writes/checkpoints at the
same time. `effects.Log` serializes its own connection, but `outbox.Open` opens
another writable connection to the same session database. There is therefore
no application-wide single-writer guarantee; outbox writes/checkpoints can
overlap effect-log commits. This research does not demonstrate the race in
Airbag. Plan a tested driver update to a release embedding SQLite 3.51.3
or later (or an explicitly patched branch). The official fix is documented in
[the 3.51.3 release notes](https://sqlite.org/releaselog/3_51_3.html) and
[WAL-reset details](https://sqlite.org/wal.html#walresetbug).

This is routine dependency maintenance, separate from performance-driven engine
migration. Test the actual embedded `sqlite_version()`, old-log reads, prepared
inserts, FULL WAL and supported cross-compilation targets after updating; align
the modernc libc version as required by the driver's documentation.

## When a migration would be justified

After buffered audit and cache changes, migrate only if storage CPU or durable
commit latency remains a material measured fraction of end-to-end runtime. A
durable append journal plus a derived SQLite review index is then the next
focused prototype. If one-record FULL commits are already dominated by disk
sync, changing KV engines while preserving the barrier is unlikely to provide
the desired improvement. If buffering makes SQL CPU dominant, simplify the
schema and measure it before maintaining a second authoritative storage format.
