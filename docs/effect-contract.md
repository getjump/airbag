# Described operations and their handlers

Airbag's sandbox observes operations made by arbitrary programs. Describing an
operation does not prove what a script does. Shell models predict, runtime
backends intercept attempts, and a successful handler reports a result; these
are different kinds of evidence. The existing filesystem and network boundaries
remain responsible for subprocesses.

The public `operation` package defines a versioned, closed set of external action requests.
The first variant describes creation of a GitHub pull request: owner/repository,
base and head branch, exact head commit, title, body bytes and draft status.
It is data, with no shell or closure to execute. A SHA-256 digest covers all the
validated fields. It is an identifier for an approval, not a signature.

The schema is `airbag.operation/v1`. Unknown kinds or schemas have no handler and
are refused. Supported operations must validate their inputs and name the
authority they require. `pull_requests:write` describes what a handler uses; it
does not restrict the user's token by itself.

The outbox stores the immutable request and digest alongside its existing intent
and append-only status history. Old sessions retain their original layout and
behavior. JSON review adds `request` and `request_digest` without changing the
meaning of existing fields. Old binaries must not execute new typed variants.

The pure lifecycle reducer permits pending → approved → running → done/failed/
unknown, or rejection before execution. Approval binds the full request digest.
An immediate SQLite transaction durably consumes that grant before execution;
two competing handlers cannot both claim it. Completed, failed, rejected and
unknown are terminal. A queued ticket does not mean a remote action succeeded.
SQLite WAL with synchronous=FULL persists approval and claim barriers. Reopen
tests verify the stored history; they do not simulate power failure.

The first handler is a separate increment. Preview must perform no external
mutation, and execution must not silently fall back to an arbitrary host command.
External services are not part of a filesystem transaction: sent data cannot be
recalled, and an uncertain result cannot safely be retried automatically.

Policy `Decide` already takes an explicit snapshot of labels and command context.
It can evaluate recorded inputs without executing their effects. Law tests check
that replay is deterministic, inputs stay unchanged and an additional matching
deny cannot expand permission. This is not replay of a whole agent session.
