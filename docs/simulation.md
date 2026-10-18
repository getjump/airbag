# Simulated hosts

`airbag run --simulate stubs.yaml -- AGENT` answers the HTTP and HTTPS requests
to the hosts the stubs name from the stubs, in airbag's proxy. Those hosts are
never contacted: no connection is opened to them, whatever the request. Each
answered request is a row in the effect log and a line in `airbag review`, so you
see what the code tried to call.

What it is for:

- running code you do not trust (a take-home, a script someone sent) that calls
  a payment or production API, without the side effects;
- runs that do not depend on what an outside service answers today;
- fault injection: a `503`, an answer that comes too late for the client's
  timeout.

It is off by default: without `--simulate` and without `simulate:` in your own
`~/.config/airbag/airbag.yaml`, the proxy works as before.

## Stubs

A stub file holds only `simulate:`, a list of stubs. Each matches requests and
says what they get:

```yaml
# ~/stubs/payments/stubs.yaml
simulate:
  - name: charge-ok
    match: {method: POST, host: api.stripe.com, path: /v1/charges}
    respond:
      status: 200
      headers: {Content-Type: application/json}
      body_file: charge.json             # ~/stubs/payments/charge.json
  - name: charge-read
    match: {method: GET, host: api.stripe.com, path: /v1/charges/*}
    respond:
      headers: {Content-Type: application/json}
      body: '{"id": "ch_sim", "object": "charge", "status": "succeeded"}'
```

```console
$ airbag run --simulate ~/stubs/payments/stubs.yaml -- claude
airbag: simulating api.stripe.com (2 stubs): answered by airbag, never contacted
```

The code under the agent posts a charge and gets `charge.json`; a `GET
/v1/charges/ch_123` gets the second answer; anything else it sends to
`api.stripe.com` (a refund, say) is refused with `403` and not sent.

Fault injection:

```yaml
simulate:
  - name: payments-down
    match: {host: api.payments.example}
    respond: {status: 503, headers: {Retry-After: "30"}, body: maintenance}
  - name: slow-search
    match: {method: GET, host: search.example.com, path: /v2/**}
    respond: {status: 200, body: '{"hits": []}', delay: 45s}   # past a 30-second client timeout
```

| Field | Meaning |
|---|---|
| `name` | Shown in the log and the review. Printable ASCII without spaces, at most 64 bytes, unique. Default: the file's name and the stub's place in it (`stubs.yaml#2`). |
| `match.host` | Required. A name (`api.stripe.com`) or the names under one (`*.stripe.com`, which does not cover `stripe.com` itself, and needs two labels after `*.`). With no port it covers ports 80 and 443, as an allowlist entry does; `host:8443` covers that port only. A name, not an IP address. |
| `match.method` | `GET`, `POST`, ...; empty is any. Upper-cased; the request's method must be exactly that. |
| `match.path` | Exact (`/v1/charges`), or a glob: `*` matches within one path segment, `**` across segments (`/v1/**` is everything under `/v1/`). Empty is any path. The path is matched as decoded, without the query. |
| `match.query`, `match.headers` | Values the request must have: each key needs a value that matches its glob, where `*` matches anything (`{currency: usd}`, `{Idempotency-Key: "*"}`). A query that does not parse matches no stub that asks about the query. |
| `respond.status` | 200 to 599; 200 when left out. |
| `respond.headers` | Response headers, one value each. `Content-Length`, `Transfer-Encoding`, `Connection` and the other framing headers are airbag's to set. Without `Content-Type` the answer has none: airbag does not guess one. |
| `respond.body`, `respond.body_file` | The body, inline or from a file (one or the other; below). |
| `respond.delay` | Wait before answering, as Go writes durations (`1.5s`, `2m`); at most 10 minutes. |

The first stub that matches answers, in file order; the stubs of `--simulate`
come before those of `~/.config/airbag/airbag.yaml`. A host any stub names is
simulated as a whole: a request on it that no stub matches is refused, never
passed on to the real host. Hosts no stub names keep the allowlist and the
policy, as before. The request's body is read (up to 1 MiB) and thrown away; no
stub looks at it.

## Where stubs come from

Only from you, on the host:

- `airbag run --simulate FILE`: for that run. A run with `--session` takes the
  stubs it is given, so pass `--simulate` again.
- `simulate:` in your own `~/.config/airbag/airbag.yaml`: for every session.

A repository's `airbag.yaml` cannot set them, and `airbag run` refuses to start
if it does: its stubs would decide what the agent and its programs are told (an
answer from the model API, say) and which files on this machine are served to
them. Both files are read on the host when the session starts. The agent writes
only to its branch, so it cannot change this run's stubs, and a change it makes
to a stub file reaches your real files only through `airbag apply`, after review.

A `body_file` is named relative to the directory of the file that names it, and
must stay there: no `..`, no absolute path, no link (airbag opens it with
`os.Root`). It must be a regular file, at most 4 MiB, and not a secret file by
name (`.env`, a key: the names FUSE watches), so a stub cannot hand the agent a
secret the session would otherwise be labelled for reading. A stub file in your
home directory itself may not name body files: everything in it would be in
reach. Body files are read once, when the session starts. Anything else in the
stub file's directory and below can be served, so keep stub files in a
directory of their own.

## HTTPS

For a simulated host the proxy ends the agent's TLS itself, with the session's
certificate authority, the one [bound credentials](policies.md#credentials) use.
The CA is made for the session, its key stays in airbag's memory, and its name
constraints permit only the simulated names and the hosts a credential is bound
to, and no other name or address, so it vouches for no other site. A client checks the
certificate as it would the real one's, against the CA:

| Client | How it trusts the session CA |
|---|---|
| curl | `CURL_CA_BUNDLE` (and `SSL_CERT_FILE`) |
| Python `urllib`, `ssl` | `SSL_CERT_FILE` (OpenSSL's default paths) |
| Python `requests` | `REQUESTS_CA_BUNDLE` |
| Go on Linux | `SSL_CERT_FILE` |
| Node | `NODE_EXTRA_CA_CERTS`. Its built-in `fetch` uses the proxy at all only with `NODE_USE_ENV_PROXY=1` (Node 22.21 and later); without it, it ignores `HTTPS_PROXY` and fails, having no DNS in the sandbox |
| git, AWS CLI, pip, cargo, deno | `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `PIP_CERT`, `CARGO_HTTP_CAINFO`, `DENO_CERT` |

The bundle these point at is this machine's roots with the session CA added, so
other hosts verify as before. `test/simulate-e2e.sh` runs curl, Python, Node's
`fetch` and a Go program against stubs in a real session. What fails, with a
TLS error in the client: a client that pins the host's certificate or key
(`curl --pinnedpubkey`, mobile SDKs), one that keeps a trust store of its own
(Java's keystore, a `--cacert`), and Go programs on macOS whose `go.mod` declares
a Go version before 1.27. It fails closed: the stubbed answer does not come, and
the real host is not contacted either. airbag logs the failed handshake
(`TLS to airbag's proxy failed`), and the review shows it under Blocked. The
proxy speaks HTTP/1.1 there; a client that speaks only HTTP/2 (gRPC) fails too.

## What you see

`airbag review`:

```
Network    12 allowed: api.anthropic.com ×12
Simulated  4 answered from stubs, none sent to the host
  POST api.stripe.com/v1/charges ×2  by charge-ok
  GET api.payments.example/v1/status ×1  by payments-down
  GET api.stripe.com/v1/charges/ch_1 ×1  by charge-read

Blocked    1 by policy
  deny GET api.stripe.com/v1/refunds           no stub matches
```

`airbag review --json` has them in `network.simulated`, a list of `{"target",
"stub", "count"}` (the `airbag.review/v1` schema; the field is new, nothing else
changed), and the refused ones in `blocked` with kind `net.simulated`. In the
effect log (`airbag log`), each request is a `net.simulated` row: `allow` with
the stub's name, or `deny` with the reason. A row holds the method, the host and
the path; never the query, the headers or the body.

## The safety model

- **The host is never contacted.** The proxy checks for a simulated host before
  the allowlist, the policy and the dial, and answers it in place: no connection
  opens, through an upstream proxy or directly, whatever the request.
- **Only narrower.** A stub needs no allowlist entry and adds none. Nothing passes
  through a simulated host to the real one, not even a request no stub matches.
- **Nothing leaves, nothing comes in.** Policy rules are not asked about a
  simulated request, since it has no effect outside the machine. After a secret
  read the stubs keep answering, and their open connections are not cut. The
  answer is yours, not outside input, so it does not label the session
  `untrusted`.
- **The CA stays narrow.** It vouches for the simulated names and the credential
  hosts only, for TLS servers only, for this session only.
- **Bounds.** At most 1024 stubs. Each body is at most 4 MiB and all of them 32
  MiB together, held in airbag's memory. A delay is at most 10 minutes, under the
  proxy's 15-minute idle limit. Of a request's body airbag reads at most 1 MiB,
  within 30 seconds; past that it answers and closes the connection. Each 64 KiB
  of an answer must go out within 30 seconds. The connections count toward the
  session's 512, as every connection through the proxy does. An answered request
  is a row in the effect log, as every allowed request is; refusals are rate
  limited as other refusals.

## A scripted model

A session in which the agent's model is a script, deterministic and free, is
not an `airbag` option yet. It works today with `test/mockapi`, the scripted
Messages and Responses API the end-to-end tests use, started inside the
session:

```console
$ go build -o ~/bin/mockapi ./test/mockapi
$ echo '[{"name":"Bash","input":{"command":"curl -sS -X POST https://api.stripe.com/v1/charges"}}]' > calls.json
$ airbag run --simulate stubs.yaml -- sh -c '~/bin/mockapi -addr 127.0.0.1:8099 -script calls.json & sleep 0.5;
    ANTHROPIC_BASE_URL=http://127.0.0.1:8099 ANTHROPIC_API_KEY=x claude -p go --dangerously-skip-permissions'
```

Claude Code runs the scripted tool call, the stub answers it, and the review
lists both. `test/simulate-e2e.sh` runs exactly this. `mockapi` is a test tool,
not a stable interface. Why it is not a stub feature: the model APIs stream
their answers, and each depends on the tool results so far, which an answer
that is always the same cannot express; the agents also send requests of their
own, which a fixed sequence would answer wrong. A stub on a
model API host can still inject a fault, such as `529 overloaded` on `POST
/v1/messages` to watch the agent retry; it takes the whole host over, so
everything else the agent sends there is refused.

Not done yet ([roadmap](roadmap.md)): passing unmatched requests on to the real
host, record and replay, answers that change from one request to the next,
matching on the request body, connection resets, IP addresses and websockets.
