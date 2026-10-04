# Review the exact PR before publication

With `defer: [gh pr create]`, supported create calls become a typed
`github.pull_request.create` request. Capture, preview, policy, approval and
execution interpret the same immutable payload. The shell is not an effect
type system: calling an absolute executable path bypasses a shim and remains
subject to the existing sandbox/network/credential boundaries.

## Workflow

Configure the workspace:

```yaml
defer: [gh pr create]
rules:
  - name: pr-destination
    when: effect.kind == "github.pull_request.create" && effect.target != "my-org/my-repo"
    verdict: deny
```

Have the agent create and commit its branch before queuing publication:

```sh
git checkout -b agent/fix
# edit and commit the result, including notes.md if wanted
gh pr create --repo my-org/my-repo --base main --head agent/fix \
  --title 'Fix the bug' --body-file notes.md --draft
```

The shim freezes the body bytes and resolves `refs/heads/agent/fix` to a commit.
It emits a JSON result with `outcome: queued`, a ticket and request digest,
alongside the usual stderr notice. It has not created a PR and returns no PR
URL. Missing flags, unsupported options and capture errors are refused rather
than downgraded to a generic host command.

`airbag review --json` and `airbag outbox --json` expose the typed `result`
separately from the request: `queued` has a ticket, `completed` carries the
confirmed PR URL, and `unknown` carries uncertainty, never an invented success.

On the host:

```sh
airbag review SESSION --json
airbag outbox SESSION              # full frozen body, destination, SHA, digest
airbag outbox SESSION --json       # same preview, no network or credential use
airbag apply SESSION --branch reviewed/fix --yes
git push origin reviewed/fix:agent/fix
airbag apply SESSION               # approve the exact PR, one by one
```

The push destination is your responsibility: use the repository named in the
request. A queued legacy push stays pending after `apply --branch` and blocks
later intents; this workflow queues only the typed PR and pushes explicitly.
Alternatively, a normal `airbag apply SESSION` can first execute a reviewed
queued push, then publish the typed PR. `--yes` never authorizes typed PR
publication. Repeating apply on an already applied session processes its
outbox without reimporting files.

The imported branch's commit must equal the captured commit. If branch import
adds a commit for uncommitted leftovers, that is a different result and this
request stays pending. Commit the complete intended result before capture.
Edits to a source body file after capture do not change the PR body; the handler
publishes the displayed frozen bytes, without rereading that file on the host.

## Approval and evidence

The request digest covers repository, base/head, exact head commit, title/body
and draft status. The preview describes required authority
(`github.com`, `pull_requests:write`, repository); it does not narrow the user's
GitHub token scopes. A policy sees the typed kind, repository in `effect.target`
and digest in `effect.detail`, in addition to the existing `intent.cmd` check.
An ask rule here authorizes queuing that digest; publication still requires
the outbox's separate approval and single-use claim.

The executor resolves host `git`/`gh` outside the workspace, disables hooks and
fsmonitor for the local SHA check, ignores inherited git routing variables,
and uses an explicit GitHub.com API URL from a directory outside the workspace.
It builds a fixed REST JSON payload, without executing the captured argv or
using PR creation's interactive/autofill/push behavior. The host CLI and its
credentials/configuration remain trusted; use appropriately scoped credentials.

Before POST, both the selected local branch and the GitHub head must match the
captured commit. Approval and claim are persisted before invoking POST. After
POST, the returned PR must confirm the repository, head SHA/ref, base ref,
title/body and draft flag. Only that attested result becomes `completed`.

GitHub creates a PR from a branch, not an immutable commit argument. A remote
branch can race the check or move after creation; preflight plus response
validation cannot make that API atomic or freeze the PR's future content.
A timeout, CLI error, malformed/oversized response or mismatching response is
`unknown`, may already have created a PR, and is never automatically retried.
Later intents wait behind incomplete predecessors. Reconcile an unknown result
on GitHub manually; this version has no automatic reconciliation/retry command.

A session execution lock prevents two live executors from recovering or
publishing each other's work. After a crash, `running` becomes terminal
`unknown`. This is conservative at-most-once invocation by airbag, not an
exactly-once guarantee from the CLI, API or distributed system. Rollback can
undo local file import; it does not close a published PR or undo a push.

## Supported first version

GitHub.com, a head branch in the destination repository, SHA-1 commits, explicit
`--repo/-R`, `--base/-B`, `--head/-H`, `--title/-t`, one of `--body/-b` or
`--body-file/-F`, and optional `--draft/-d`. Body files must be regular workspace
files, at most 256 KiB, and cannot be stdin or named secret files. Fork heads,
enterprise hosts, labels, reviewers, `--fill` and `--web` need future typed
variants or extensions. Existing queued legacy commands remain readable and
use their existing handler; they do not acquire these stronger guarantees.

Tests cover real git commits and host mock API processes, changed local and
remote heads, uncertain POST outcomes, immutable file-body capture, explicit
queued results, single-use execution, recovery and competing execution locks.
`test/typed-pr-e2e.sh` runs capture/import/publication through the actual sandbox
in Linux CI using a fake host API; it publishes no real GitHub PRs.

See [the request contract](effect-contract.md), the [GitHub CLI API interface](https://cli.github.com/manual/gh_api)
and the [GitHub pull request API](https://docs.github.com/en/rest/pulls/pulls#create-a-pull-request).
