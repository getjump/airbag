# Embedding Airbag components

Airbag remains one repository, one Go module and one default CLI. A host can
reuse its operation contracts, policy evaluator, outbox, GitHub PR interpreter
or credential proxy without creating an Airbag session or running its sandbox.
These APIs are an initial public surface, not a separately versioned stable SDK.
They currently require the Go version in the root go.mod. There are no extra
daemons to install and no new runtime/plugin protocol.

## Public packages

- `operation`: validated `airbag.operation/v1` requests, digests, pure previews,
  required authority, lifecycle transitions and results. It uses only the Go
  standard library. A request describes an action; it does not prove execution.
- `policy`: compile CEL rules and evaluate explicit effect/command/label
  snapshots. `Compile` requires an explicit allow or deny no-match fallback;
  a deny names the rule `fallback`. A nil or uninitialized engine denies.
  Evaluation performs no filesystem, network, credential, approval or
  persistence operations. Airbag's existing internal loader/gate retain the
  native allow fallback, trusted config sources, repository restrictions,
  labels and approvals.
- `audit`: the shared record and `Recorder` interface. The SQLite implementation
  stays internal. `Recorder.Add` has no durability acknowledgement. It must not
  replace runtime admission's commit-before-allow or secret-read barriers.
- `outbox`: immutable typed requests, FULL-WAL approvals/claims, status history,
  preview rendering and the execution lock. It can have a private database of
  its own rather than sharing an Airbag session's database. Legacy argv intents
  remain for the CLI's compatibility; they are not a general interpreter API.
- `githubpr`: preparation and execution of the frozen PR payload through a
  caller-supplied trusted API transport. Preparation verifies the remote head
  without publishing. A prepared value copies the request and POST payload;
  repeated publication calls reuse its result rather than repeat the POST.
  The returned PR must match the exact destination, branches, commit, title,
  body and draft state. An observed GitHub 4xx refusal fails; transport errors,
  5xx responses or a mismatching response are `unknown`. Neither retries.
- `creds`: host-side credential resolution, placeholders and masking. Binding
  sources and destinations must come from the trusted operator, not the agent.
- `proxy`: the existing HTTP/CONNECT allowlist and credential mediation, with a
  `Gate` interface and an `audit.Recorder` instead of concrete Airbag session
  objects. The owner serves it with `p.Serve(l)`, or
  `p.HTTPServer().Serve(p.LimitListener(l))`, closes the listener, and calls
  `Proxy.Close` to cancel tracked requests and hijacked tunnels.

Public packages do not depend on Airbag session/runtime state or the internal
policy loader and audit database. Proxy shares the small, stateless internal
connection limiter with the control server. The CLI imports and uses
these same implementations; this is not a second policy engine or handler.
Predicted effects, observed attempts and completed operations retain their
separate representations. Existing operation/review JSON and SQLite layouts
are unchanged.

## A pure preview and policy decision

```go
preview, err := request.Preview() // no credentials, filesystem or network
if err != nil {
    return err
}
engine, err := policy.Compile([]policy.Rule{{
    Name: "review-publication",
    When: `effect.kind == "github.pull_request.create"`,
    Verdict: policy.Ask,
}}, policy.Deny)
if err != nil {
    return err
}
decision := engine.Decide(policy.Input{Effect: policy.Effect{
    Kind: request.Kind,
    Target: preview.Authority.Resource,
    Detail: preview.RequestDigest,
}})
```

`ask` is a decision, not a saved approval. The embedding host must obtain the
human decision and bind it to the digest in trusted storage. A policy decision
does not restrict a token's provider-side scopes or enforce arbitrary processes.

## An independent outbox host

Use a private directory outside the untrusted agent's filesystem. Queue the
validated request with `Box.Push` and render its preview. `Approve(id, digest)`
records a human authorization of those exact bytes; a different digest fails.

The executor holds `LockExecution` across loading current state, crash recovery,
preflight, durable claim, publication and recording the outcome. It verifies
the selected local result and remote head before `Claim`, and verifies the local
selection again after slow remote checks. The CLI's apply path still requires a
complete file import or an explicitly selected branch before publication.
An independent embedding must define and enforce its own equivalent selection
rule; the GitHub interpreter does not know its workspace/import semantics.

Only after `Claim(id, prepared.Digest())` commits may the executor call
`prepared.Publish(ctx)`. Bind the returned result to the ticket, map its outcome
to `done`, `failed` or `unknown`, and save it with `Update`. A running ticket
found after a crash becomes unknown while holding the execution lock; it must not be retried
automatically. Inspect earlier incomplete/unknown operations before executing
anything that depends on them. After inspecting the remote, the trusted human
can settle an unknown ticket with `Box.Resolve`; resolution does not publish
or authorize another attempt. The public store does not schedule dependencies.

The API callback belongs to the trusted host: bind it to GitHub, limit response
sizes and time, honor cancellation, and disable implicit mutation retries.
Return `githubpr.HTTPError` only for a directly observed GitHub error response;
a timeout or CLI diagnostic cannot establish an HTTP refusal.
The existing CLI adapter continues using a trusted host `gh`, sanitized routing
environment and fixed GitHub API endpoints. No callback or credential is
accepted from an operation request. A prepared value's single-use guard is
local to that value: durable claims protect across processes and restarts.
This is not distributed exactly-once execution, rollback of remote publication,
or atomic freezing of a mutable remote branch.

`test/sdk-client/client_test.go` contains a runnable independent host example.
It queues and previews a PR, rejects a changed approval digest, reopens storage,
claims once, publishes to a host-only fake API, and records success, refusal
or uncertainty.
It creates no real PRs and runs without Airbag's sandbox, session metadata or CLI.

## An independent egress host

Supply a `Gate` and recorder to the proxy. A gate owns policy/approval/label
state; `AllowsHost` may grant an explicit exception to the allowlist. With no
`Gate`, the allowlist alone decides. `Tainted` must return a reason whenever
the labels are not known to be clean (they could not be read, say): an empty
answer keeps every allowed host open. Credential bindings and their real values
remain with the trusted host. The embedding must give the client the proxy CA
and placeholders, never its real credential values.

Serve the proxy with `p.Serve(l)`, or `p.HTTPServer().Serve(p.LimitListener(l))`
for a server of your own: either one caps the connections to the proxy and
closes idle ones. Handing `p` to another `http.Server` (`httptest.NewServer`,
say) drops both bounds. `proxy.New` sets the defaults; a `Proxy` made as a
struct literal gets the same ones: the address guard, each `Limits` field left
zero (a negative one turns that bound off), and no upstream proxy when
`Upstream` is nil. A nil `Log`, or a `Gate` that holds a nil pointer, is
answered with 503 rather than served without a record or a policy.

The sandbox/container/VM must force traffic through this proxy. Proxy environment
variables alone do not prevent bypass. If a secret read narrows egress, the
trusted collector must update the label and call `Cut` before releasing bytes.
Neither the standalone proxy nor the pure policy evaluator observes arbitrary
filesystem access. This API does not add LLM DLP, JIT credential issuance or TTL.

The external-client test runs a real TLS upstream and checks placeholder
substitution, response masking, a policy denial on an allowlisted destination,
and a custom recorder without SQLite/session objects. It also serves a struct
literal `Proxy`: loopback is refused, and admission stops at the default
`MaxFlows`.

## Host authority and runtime adapters

`internal/sandbox/host.go` is the common owner of policy gate, persisted labels,
audit, credentials, mirror, outbox, proxy/control servers and TCP forwards.
Linux chooses Unix proxy sockets and a workspace overlay; Darwin chooses a TCP
proxy and a workspace clone. The shared control root is supplied explicitly.
Launch mechanisms, mount/profile setup, agent environment and workspace import
remain runtime-specific. No unused universal backend interface is introduced.

Partial startup unwinds acquired resources. Shutdown closes servers/listeners,
tracked proxy flows and forwards before closing storage. Forward dials are
cancelled. The same owner is used by both native platform entry points.
The lifecycle tests exercise startup failure, close, repeated close and resume.

The host owner does not claim equivalent capabilities between native, gVisor
and microVM execution. No build speed improvement is claimed: package
boundaries do not remove FUSE crossings or audit commits.

## Validation

`go test ./...` and the race suite exercise existing storage, policy, proxy,
review/apply and typed publication behavior. `sh test/sdk-client-e2e.sh` copies
the client into a fresh external Go module, compiles it with the local Airbag
replacement, runs it under the race detector when cgo and a C compiler are
available, and checks the public dependency graph. The client still runs
without the race detector in environments such as the WSL job. CI runs that
external client and host lifecycle on Linux and macOS;
the existing Linux sandbox E2E still exercises the complete CLI workflow.
