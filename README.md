# airbag

**Approve outcomes, not commands.** Run your coding agent without permission
prompts inside a copy-on-write branch of your machine. Review one diff at the end,
then apply it or throw it away.

```console
$ airbag run -- claude --dangerously-skip-permissions
$ airbag run -- codex --dangerously-bypass-approvals-and-sandbox   # or Codex
$ airbag review
$ airbag apply        # or: apply -i, apply --branch NAME, or: airbag discard
$ airbag rollback     # undo the last apply
```

![demo: the agent deletes src, reads .env, tries to send it out, plants a line in ~/.bashrc and pushes; airbag review shows all of it; discard, and nothing happened](demo/demo.gif)

The demo runs the real Claude Code; the "model" is `test/mockapi` playing a fixed
script, so it is repeatable without an account (`demo/demo.sh`). `agent ▶` lines are
the calls the model makes, `agent ◀` what the agent sends back. More scenes, one GIF
each, in `demo/`: `sandbox`, `codex`, `ask`, `apply`, `mirror` (`demo/scenes.sh NAME`).

## How it compares: bubblewrap, built-in sandboxes, branch tools

Isolation is not the difference. On Linux, Claude Code's and Codex's built-in
sandboxes run on bubblewrap, and airbag uses the same kernel namespaces. What
differs is when you decide, and what you get to see.

Say you ask an agent to clean up a repository, and it deletes `src`, reads
`.env`, tries to post it to a paste site, appends a line to `~/.bashrc` and
pushes.

- **bubblewrap:** you decide up front. Mount the workspace read-write, and the
  files are gone with no record of what happened; read-only, and the agent's
  work is lost when it exits. The network is on or off.
- **Built-in sandbox:** the agent stops for approval as it goes: a write
  outside the workspace, a new domain. You answer prompts mid-run and never see
  the whole result at once.
- **airbag:** the agent runs without stopping in a branch of your machine.
  Afterwards one review shows all of it: `src` deleted, `.env` read, the upload
  blocked, the `~/.bashrc` line flagged as persistence, the push waiting in the
  outbox. `airbag discard`: the files and `~` are as they were, and the push never
  left. (A request to an allowed host would have happened when it was made; see
  below.)

| | bubblewrap | built-in sandbox | airbag |
|---|---|---|---|
| Isolation | namespaces | bubblewrap (Codex adds Landlock, seccomp) | namespaces |
| Files | read-write in place, or thrown away | workspace in place, asks outside it | copy-on-write branch of workspace and `$HOME`; apply all, part or none |
| Network | on or off | domain allowlist through a proxy | allowlist, every host logged, package mirror, cut on a secret read |
| Irreversible actions | not handled | blocked or asked | queued in the outbox, run after review |
| Policies | mounts | tools, commands, domains | CEL rules over effects; `ask` with `airbag approve` |
| Secrets | hide paths | hide paths | a read labels the session and narrows egress; values masked in shell output |
| One view of what changed | no | no | effect log, steps per tool call, hosts, packages |
| You decide | before the run | during the run | after the run, once |

Other tools also let you decide after the run, for files at least:

| | Files | Network | Pushes, publishes, API calls | Secrets |
|---|---|---|---|---|
| [nono](https://github.com/nolabs-ai/nono) `--rollback` | writes land in place; snapshot before, diff after, restore what you pick | blocked by default, L7 proxy | asked live by its supervisor | stand-in credential, real one injected by the proxy |
| [try](https://github.com/binpash/try) | overlayfs branch of one command, commit or not | unrestricted | run as they happen | not handled |
| [AgentFS](https://github.com/tursodatabase/agentfs) | copy-on-write branch of the working directory (SQLite delta), `agentfs diff`; no apply command | not controlled | run as they happen | not handled |
| [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) in clone mode, or [Code Airlock](https://github.com/Trivo25/code-airlock) on top of it | microVM with a private clone, host repo read-only; review and merge with `git fetch`, `git diff` | allowlist through a proxy | not held | proxy injects credentials, values stay outside the VM |
| Claude Code sandbox and checkpoints | writes in the workspace, `/rewind` restores the agent's own file edits, not Bash's | allowlist through a proxy, asks for new domains | auto mode's classifier blocks some | denied or masked behind a proxy |
| airbag | copy-on-write branch of the workspace and `$HOME`; persistence flagged; apply all, part or none | allowlist, every host logged, mirror, cut on a secret read | queued in the outbox, run after review | hidden; a read labels the session and narrows egress |

What airbag adds is around the branch rather than the branch itself: the outbox
for actions that leave the machine, the `$HOME` branch with persistence called out,
a label that follows a secret read through the rest of the session, and one review
that works the same for any agent, on your own toolchain without a VM. Whether that
beats a VM clone or nono for a given team is a matter of measuring, not of this
table. Tools that govern effects at runtime in depth, such as
[agentsh](https://github.com/canyonroad/agentsh) (file, process and network policy
with approvals, an LLM proxy with DLP), go further than airbag's policies do. (As of
October 2026, from each project's documentation.)

### What waits for you, and what does not

| | Until you decide | Examples |
|---|---|---|
| Stays local until `airbag apply` | the workspace and `$HOME` | edits, deletions, new files, a line in `~/.bashrc` |
| Waits in the outbox, runs after review | what airbag intercepts | `git push` |
| Decided when it happens, by the allowlist and policy | every other network request | model API calls, a request to a host you allowed, packages through the mirror; `ask` holds a call until you approve it |

A call to an outside service cannot be held or undone after the fact, so for those
the allowlist and policy decide beforehand. Review shows that they happened.

airbag sets up its namespaces itself. Could it run on bubblewrap underneath?
Not yet: bubblewrap 0.9, which Ubuntu 24.04 ships, cannot make the overlay the
branch needs, and FUSE, the proxy bridge and the agent settings would stay
airbag's anyway. See [docs/bwrap-backend.md](docs/bwrap-backend.md).

## What the agent gets

- **A branch of the world.** The workspace and `$HOME` are overlayfs branches; the
  rest of the host is read-only. Nothing the agent writes reaches your files before
  `airbag apply`.
- **One way out.** The sandbox has no network interface besides loopback and no
  DNS. Traffic leaves only through airbag's proxy, which allows model APIs
  (`--allow HOST` adds more) and logs every host. Package registries are reached
  only through the mirror. Allowed hosts are reached on ports 80 and 443;
  another port needs an entry that names it (`--allow git.corp:8443`). An
  allowed name that resolves to this machine, loopback, link-local (cloud
  metadata) or multicast is refused: the address is checked as the proxy
  connects, so a DNS answer cannot change between check and use.
- **Local services, by name.** `--allow tcp://127.0.0.1:5432` (or `allow:` in
  `airbag.yaml`) gives the agent `127.0.0.1:5432` in the sandbox, relayed by airbag
  to that address: a dev database, a cache, a service from `docker compose`. Each
  connection is checked by policy (as a `net.connect` effect) and logged as
  `net.tcp`. After a secret read, forwards to other machines are refused and cut;
  forwards to this machine stay. The Docker socket itself stays hidden.
- **A package mirror.** Go, npm, pip, uv and yarn go through
  `http://airbag.mirror`, a read-only caching mirror of proxy.golang.org, npm and
  PyPI. Review lists every package and version the agent pulled; artifacts are
  cached across sessions.
- **An outbox.** `git push` returns `queued` and runs on the host after you approve
  it. Pushing around the shim fails at the proxy. If the session put git config or
  hooks into the repository, its pushes wait for `airbag apply --trust-git` and
  run with hooks off. A push cut off by a crash is reported as of unknown outcome
  and never run again.
- **No credentials.** `~/.ssh`, `~/.aws`, `gh`, `docker`, `kube` and similar are
  hidden, and so are credential-like environment variables (`*TOKEN*`,
  `*SECRET*`, `*API_KEY*`, ...) except the agents' own API keys; `--pass-env NAME`
  keeps one. Decryption keys and decrypted secrets are hidden too: sops and age
  keys, sops-nix's runtime secrets, `pass`, Vault, rclone, keyrings; `hide:` in
  `airbag.yaml` adds paths. Host sockets (docker.sock, D-Bus, ssh-agent, X11,
  Wayland) are out of reach: `/run`, `/tmp` and `/dev/shm` are private. Daemons
  that keep their socket elsewhere are hidden by name: Incus and LXD (root for
  their admin group) and the Nix daemon, whose builds reach the network outside
  the proxy; `--nix-daemon` gives the agent Nix anyway.
- **Watched secrets.** The workspace's secret files are served read-only through
  FUSE (`.env` and `.env.*` at any depth, private keys, `.npmrc`, `.pypirc`,
  cloud credentials, `*.tfvars`). The first read by anything but airbag taints
  the session: commands that send data out are refused, only model APIs stay
  reachable, and the mirror serves only what it has cached or what the workspace's
  lock files pin (`package-lock.json`, `yarn.lock`, `go.sum`, `uv.lock`, read from the
  real workspace before the agent starts, so a build from the lock file keeps
  working). The read returns only
  after airbag has recorded the taint and closed connections opened earlier to
  other hosts. Without FUSE the secret files are hidden instead. Known secret
  values are masked in the output of shell commands; the agent's own file tools are
  not filtered, and model APIs stay reachable, so a secret the agent reads can
  reach its model. The label stops it from going anywhere else.
- **A terminal of its own.** The agent runs in a session of its own on a
  pseudo-terminal that airbag copies to yours, as `sudo` with `use_pty` and
  `docker run -t` do. Input it pushes into its terminal (TIOCSTI) or modes it
  sets stay in that pseudo-terminal, never in the shell you return to; a
  seccomp filter refuses TIOCSTI and TIOCLINUX as well, and the agent runs
  with `no_new_privs`. Ctrl-C, Ctrl-Z with `fg`, and resizing work as usual.
- **A strict mode.** `airbag run --strict` also keeps the agent from creating
  user namespaces, so the kernel features only a user namespace exposes stay
  out of its reach. It is off by default because common tools need them:
  Codex's own `--sandbox` modes and Chromium's sandbox fail under it (run
  Codex with `--dangerously-bypass-approvals-and-sandbox`, Chromium with
  `--no-sandbox`).
- **More than one run.** `airbag run --session last -- claude --continue` runs the
  agent again on the branch of a stopped session: it sees its own earlier changes,
  the outbox and the effect log continue, and what the session learned stays (a
  secret read in the first run still narrows egress in the second). Iterate
  "agent, review, tell it what to fix, agent again" without applying in between.
- **Its own state.** Transcripts and logins (`~/.claude/projects`, `~/.codex/sessions`,
  tokens) pass through, so discarding a branch does not log you out.

## What the review shows

```
Workspace  /home/me/api
  Files    +3 ~2 -1    (git internals: 14 files)
  + .git/hooks/pre-commit  persist
  + leak.txt  secret in diff
Home       1 changes outside the workspace
  ~ ~/.bashrc  persist
Network    31 allowed: api.anthropic.com ×30, proxy.golang.org ×1
           1 denied: paste.example.net:443 ×1
Outbox     1
  i-1  git push origin feature/retry               pending
```

`airbag review --attention` prints only what needs a decision: secret reads, flagged
changes, many deletions, waiting pushes, blocked calls. `airbag review --json` prints
the whole review as data for editors and CI, with a versioned schema
(`airbag.review/v1`; fields are only added within a version).

It flags persistence (git hooks, shell rc files, CI config, agent settings), new
executables, changes outside the workspace and values from your `.env` files that
ended up in the diff. `apply` refuses to overwrite files you changed on the host
while the agent worked. `apply -i` goes through the changes one by one (git
internals and caches come as one piece each) and keeps the rejected ones in the
session; `apply --only PATH` takes just part of the branch.

An apply is all or nothing: before a real file changes, what was there moves into
the session, so a step that fails puts back the ones before it. `airbag rollback`
undoes the last apply the same way, and the agent's changes go back into the session
to apply again or discard; a file you edited after the apply is left as it is. A
push that already ran is not undone.

`apply --branch NAME` leaves your working tree alone and puts the result on a new
branch of the repository instead: the agent's commits, fetched with their history,
then one commit with whatever it left uncommitted (files your `.gitignore` excludes
stay out). Your index, uncommitted edits, `.git/config` and hooks are not touched,
and the agent's git config and hooks are never carried over. Review and merge it
with git as you would a colleague's branch. Changes in `~` stay in the session.

## Policies

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

Which tools an agent may call is the agent's own setting (Claude Code's
permissions, Codex's configuration), and airbag does not duplicate it. airbag
governs the effects any tool has: files, network, processes and secrets.

## Install

```console
$ curl -fsSL https://raw.githubusercontent.com/getjump/airbag/main/install.sh | sh
$ airbag doctor
```

The script installs the latest release for Linux or macOS (amd64, arm64) into
`~/.local/bin` after checking its SHA-256 against the release. Or from source:
`go install github.com/getjump/airbag/cmd/airbag@latest`.

With Nix: `nix run github:getjump/airbag -- doctor`, or add the flake's
`packages.<system>.airbag` to your configuration. `nix flake check` runs the unit
tests, `nix develop` gives a shell with Go and the test tools.

One static binary, no daemon, no Docker. Needs Linux 5.12+ with unprivileged user
namespaces. On Ubuntu 23.10+ AppArmor restricts them; `airbag doctor` prints the
one-time profile to install. On macOS there is a native prototype (Seatbelt
around the agent, an APFS clone as the branch), not yet tried on a real Mac, and the
Linux VM setup that works today; see [docs/macos.md](docs/macos.md).

## Status

Early v0, not yet tried by anyone outside the project. Working on Linux: sandbox,
branch, proxy with allowlist and address checks, mirror, git push outbox, review
(text, `--attention`, `--json`), diff, apply with conflict check (all or nothing),
`apply --branch`, `rollback`, `run --session`, `tcp://` forwards, discard. On macOS:
a prototype (see above). Claude Code gets airbag's hooks as
read-only managed settings, Codex as a read-only `/etc/codex/requirements.toml`
(unless the host has its own), so the review shows which tool call changed which
file. Codex's own SQLite state folds into one review line.
`bash` and `sh` are shimmed: each `-c` script is parsed, every command is matched
against a model of its effects (`rm -rf` deletes, `curl -d` sends data out, `git
config core.hooksPath` persists), and known secret values (from `.env` and
credential-like variables) are masked in its output. The models are predictions
for review and early refusals; scripts and programs they do not cover are
`opaque`, and the boundary for those is the sandbox, the proxy and FUSE.

Tests: `go test ./...`, then as a regular user every `test/*e2e.sh` and
`python3 test/ctrlc.py` (CI runs them on each push); `test/claude-e2e.sh` and
`test/codex-e2e.sh` drive the real Claude Code and Codex binaries against
`test/mockapi`, a scripted mock of the Messages and Responses APIs. With a real login, follow [docs/manual-test.md](docs/manual-test.md).

Each session keeps one SQLite database, `effects.db`: the effect log and the
outbox, with the history of every intent's status. Triggers make all of it
append-only, so `sqlite3` answers questions the review does not.

Not yet: secret handles (the agent sees a placeholder, airbag substitutes the
value at an allowed boundary), passing Codex's SQLite state through (transcripts
in `~/.codex/sessions` survive a discard, its thread index and memories do not). Tools that ignore the mirror settings cannot reach registries; `--allow HOST`
opens one directly. After a secret read the mirror serves its cache and what the
lock files pin; pnpm-lock.yaml, poetry.lock and hashed requirements files are not
read yet.

What is next and what is deliberately left for later, with reasons:
[docs/roadmap.md](docs/roadmap.md). How to tell whether airbag is worth using,
against the alternatives: [docs/evaluation.md](docs/evaluation.md).

## Threat model

airbag protects against accidents and casual exfiltration by an agent you let run
without prompts. It is not a VM: the kernel is shared, and whatever the agent reads
is still sent to the model API.

## License

Apache-2.0
