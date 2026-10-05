# Policies

`airbag.yaml` in the repository (and `~/.config/airbag/airbag.yaml`) adds hosts and
rules. Rules are [CEL](https://cel.dev) expressions over effects. Some effects are
observed, so a rule holds whatever program causes them: every connection passes
the proxy (`net.connect`), every secret read passes FUSE. Others are predicted from
a command line by built-in models (`net.egress` for `curl -d`, `fs.delete` for
`rm`): a rule on those refuses early and marks the review, but a script can do
more than its command line shows, so for them the sandbox and the review are the
boundary.

```yaml
allow: [api.github.com]
rules:
  - name: ask-before-sending
    when: effect.kind == "net.egress"        # curl -d, scp, npm publish, ...
    verdict: ask
    message: data leaves the machine
  - name: never-prod
    when: command.line.contains("--context prod")
    verdict: deny
```

Rules can also read the session's labels, `session.labels`: `secret` once
the session read a secret file, `untrusted` once it pulled content from a web
host. That keeps outside input from driving an irreversible effect:

```yaml
  - name: no-push-after-web
    when: '"untrusted" in session.labels && effect.kind == "intent.git_push"'
    verdict: deny
```

Rules are type-checked when airbag starts: a misspelled field (`effect.knd`) is an
error, not a rule that never matches. A `deny` or `ask` rule that fails while
evaluating (say `command.argv[0]` on an effect with no command) counts as
matched, and the message says so; guard such rules with `command.argv.size() > 0`.

Verdicts are `allow`, `deny` and `ask`; a deny anywhere wins. An `ask` blocks the
command and tells the agent to have you run `airbag approve a-N`; after that the
retry passes. For Claude Code the answer arrives through a PreToolUse hook, before
the command runs; Codex gets the same through its hooks. The repository's file is read from the real workspace, so the
agent cannot loosen its own rules, and a change to it shows up in review as
`persist`.

## Deferred commands

A command that acts on the world with your credentials, such as opening a pull
request or publishing a package, fails in the sandbox: the agent has neither the
token nor the network for it. `defer:` lets such calls wait in the outbox instead:

```yaml
defer:
  - gh pr create
  - gh release create
  - npm publish
```

Each entry is a program and the words that pick its calls: `gh pr create` selects
PR creation, including `gh -R org/repo pr create`, while `gh pr list` runs
in the sandbox as before. airbag puts a shim for the program first in the agent's
PATH. The agent gets `queued as intent i-N` and carries on; review lists the call
with the files it names. A call by full path (`/usr/bin/gh`) skips the shim and runs
in the sandbox, so `defer:` is a convenience: the boundary is still that the agent
holds no credentials.

New `gh pr create` calls use a [typed request and preview](typed-pr-outbox.md):
commit the result first and supply explicit `--repo`, `--base`, `--head`,
`--title` and `--body` or `--body-file`. The body bytes and exact head commit are
frozen; incomplete/unsupported calls are refused. `airbag outbox [ID] [--json]`
shows the exact proposed PR without a network call. Execution rebuilds a fixed
GitHub API request after separate approval, checks the selected and remote
commits, and verifies the returned PR. An uncertain result is never retried:
the intents after it wait until you check GitHub and record what happened with
`airbag outbox resolve INTENT done|failed`.
It can run after branch import when that branch matches the captured commit
and the intended remote head has already been pushed. Other deferred commands
and old sessions use the generic behavior below.

The command runs on your machine, with your environment and credentials, after
`airbag apply` has written the files:

- you confirm each one; `--yes` does not run them;
- the program comes from your PATH, never from the workspace;
- files it names in the workspace must hold what they held when it was queued,
  and a file outside the workspace is refused when the agent queues the call
  (`/tmp` in the sandbox is not yours); pass text inline or put the file in the
  workspace; a call that names a secret file (`.env`, a key) is refused, and so is
  one that names the session's own storage;
- while links the session put in your files lead out of the workspace or to a
  secret file (`notes.md -> .env`, `docs -> ~/.config`, a venv's interpreter in
  `~/.local`), the commands wait, whatever their arguments say: an argument that
  is or runs through such a link would read or write there without showing it.
  Links to installed programs (`/usr/bin/python3`: root's, in root's
  directories) do not count; links to any directory outside, `/usr` included, or
  to a configuration file anyone may read, do. Remove
  or replace the links, or after inspecting them run `airbag apply --trust-links`;
- after a failure the rest wait in that apply, since a pull request without its push
  means nothing; after an unknown outcome they wait until you record what happened
  (`airbag outbox resolve`); after `apply --branch` generic commands wait, because the
  working tree is not the result; if the session changed `.git/config` or hooks, they wait for
  `--trust-git`, as pushes do, and run with hooks and fsmonitor off;
- rules see the call as an `intent.cmd` effect, so
  `'"untrusted" in session.labels && effect.kind == "intent.cmd"'` can refuse
  it, and review flags a call that carries a value from your secret files.

It reads the workspace as applied, as it would if you ran it yourself after
merging: `npm publish` runs the scripts in `package.json`, `make release` the
`Makefile`. Review those first.

## Credentials

Some tasks need a token to work at all: listing pull requests, reading a private
API. Bind the token to the hosts it is for, in your own
`~/.config/airbag/airbag.yaml` (a repository's `airbag.yaml` cannot, since it
would decide where your tokens go):

```yaml
credentials:
  - name: github
    hosts: [api.github.com, uploads.github.com]
    source: command:gh auth token      # or env:GH_TOKEN, or file:~/.config/x/token
    env: [GH_TOKEN]
```

The agent sees `GH_TOKEN` set to a placeholder of the same shape (`ghp_` and
random characters). For the bound hosts, and only for them, airbag terminates
TLS with a certificate authority made for the session: its key stays in
airbag's memory, and its name constraints permit only those names (and the
names under them) and no name of the other kind (no IP address when the hosts
are names, no DNS name when they are addresses), so a verifier that checks
constraints, as Go and OpenSSL do, accepts it for no other site. Its
extended key usage is TLS server authentication only. airbag
replaces the placeholder with the value in the request's
headers (Basic credentials included) and query, checks the real host against this
machine's roots, and replaces the value with the placeholder in the response, so a
host that echoes the request does not hand the token to the agent. A request whose
`Host` names another site is refused, so a server that hosts several sites (a CDN)
cannot be asked to route the token to one the binding does not name (domain
fronting). The value is
read when the session starts and is never written to disk. Tools in the sandbox
trust the session's authority through `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` and
the like.

Because airbag sees these requests, review lists each one with its method and
path, and rules can match them as `http.request` effects:

```yaml
rules:
  - name: github-read-only
    when: effect.kind == "http.request" && effect.target.startsWith("api.github.com/") && effect.detail != "GET"
    verdict: deny
    message: reads only; open the pull request with `defer:`
```

The agent can do with the token whatever the token allows on those hosts,
right away: bind a token with the least scope that does the job, and use rules or
`defer:` for writes. After a secret read the bound hosts are cut off like any host
that is not a model API. Not covered: tokens in request bodies (OAuth flows),
tools that pin certificates or keep their own trust store (Java), Go programs on
macOS whose `go.mod` declares a Go version before 1.27, most Go tools today (they
ignore `SSL_CERT_FILE` whichever Go builds them), and Node's built-in `fetch`, which ignores
`HTTPS_PROXY` unless `NODE_USE_ENV_PROXY=1` (Node 22.21 and later). A protocol
upgrade (a websocket) to a bound host is refused: airbag could not keep the
value out of the upgraded stream.

## Tools and effects

Which tools an agent may call is the agent's own setting (Claude Code's
permissions, Codex's configuration), and airbag does not duplicate it. airbag
governs the effects any tool has: files, network, processes and secrets.
