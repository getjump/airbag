# airbag

**Approve outcomes, not commands.** Run your coding agent without permission
prompts inside a copy-on-write branch of your machine. Review one diff at the end,
then apply it or throw it away.

```console
$ airbag run -- claude --dangerously-skip-permissions
$ airbag run -- codex --dangerously-bypass-approvals-and-sandbox   # or Codex
$ airbag review
$ airbag apply        # or: airbag apply -i, or: airbag discard
```

![demo: the agent deletes src, reads .env, tries to send it out, plants a line in ~/.bashrc and pushes; airbag review shows all of it; discard, and nothing happened](demo/demo.gif)

The demo runs the real Claude Code; the "model" is `test/mockapi` playing a fixed
script, so it is repeatable without an account (`demo/demo.sh`). `agent ▶` lines are
the calls the model makes, `agent ◀` what the agent sends back. More scenes, one GIF
each, in `demo/`: `sandbox`, `codex`, `ask`, `apply`, `mirror` (`demo/scenes.sh NAME`).

## Why not bubblewrap, or the agent's own sandbox?

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
  outbox. `airbag discard`, and none of it happened.

| | bubblewrap | built-in sandbox | airbag |
|---|---|---|---|
| Isolation | namespaces | bubblewrap (Codex adds Landlock, seccomp) | namespaces |
| Files | read-write in place, or thrown away | workspace in place, asks outside it | copy-on-write branch of workspace and `$HOME`; apply all, part or none |
| Network | on or off | domain allowlist through a proxy | allowlist, every host logged, package mirror, cut on a secret read |
| Irreversible actions | not handled | blocked or asked | queued in the outbox, run after review |
| Policies | mounts | tools, commands, domains | CEL rules over effects; `ask` with `airbag approve` |
| Secrets | hide paths | hide paths | reads label the session; values masked in output |
| One view of what changed | no | no | effect log, steps per tool call, hosts, packages |
| You decide | before the run | during the run | after the run, once |

Deciding after the run works for what airbag can branch: files, `$HOME`, a push
that has not left yet. A call to an outside service cannot wait or be undone, so
there the policy decides beforehand, or `ask` holds the call until you approve
it.

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
  only through the mirror.
- **A package mirror.** Go, npm, pip, uv and yarn go through
  `http://airbag.mirror`, a read-only caching mirror of proxy.golang.org, npm and
  PyPI. Review lists every package and version the agent pulled; artifacts are
  cached across sessions.
- **An outbox.** `git push` returns `queued` and runs on the host after you approve
  it. Pushing around the shim fails at the proxy.
- **No credentials.** `~/.ssh`, `~/.aws`, `gh`, `docker`, `kube` and similar are
  hidden, and so are credential-like environment variables (`*TOKEN*`,
  `*SECRET*`, `*API_KEY*`, ...) except the agents' own API keys; `--pass-env NAME`
  keeps one. Host sockets (docker.sock, D-Bus, ssh-agent, X11, Wayland) are out of
  reach: `/run`, `/tmp` and `/dev/shm` are private.
- **Watched secrets.** The workspace's secret files are served read-only through
  FUSE (`.env` and `.env.*` at any depth, private keys, `.npmrc`, `.pypirc`,
  cloud credentials, `*.tfvars`). The first read by anything but airbag taints
  the session: commands that send data out are refused, only model APIs stay
  reachable, and the mirror serves only what it has cached. The read returns only
  after airbag has recorded the taint and closed connections opened earlier to
  other hosts. Output going back to the agent has known secret values masked.
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

It flags persistence (git hooks, shell rc files, CI config, agent settings), new
executables, changes outside the workspace and values from your `.env` files that
ended up in the diff. `apply` refuses to overwrite files you changed on the host
while the agent worked. `apply -i` goes through the changes one by one (git
internals and caches come as one piece each) and keeps the rejected ones in the
session; `apply --only PATH` takes just part of the branch.

## Policies

`airbag.yaml` in the repository (and `~/.config/airbag/airbag.yaml`) adds hosts and
rules. Rules are [CEL](https://cel.dev) expressions over effects, not over command
strings, so `bash -c` or a different spelling does not slip past them:

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
$ go install github.com/getjump/airbag/cmd/airbag@latest
$ airbag doctor
```

One static binary, no daemon, no Docker. Needs Linux 5.12+ with unprivileged user
namespaces. On Ubuntu 23.10+ AppArmor restricts them; `airbag doctor` prints the
one-time profile to install. On macOS, run airbag in a Linux VM for now; see
[docs/macos.md](docs/macos.md) for the setup, what to check, and the plan for
running natively.

## Status

Early v0. Working: sandbox, branch, proxy with allowlist, git push outbox, review,
diff, apply with conflict check, discard. Claude Code gets airbag's hooks as
read-only managed settings, Codex as a read-only `/etc/codex/requirements.toml`
(unless the host has its own), so the review shows which tool call changed which
file. Codex's own SQLite state folds into one review line.
`bash` and `sh` are shimmed: each `-c` script is parsed, every command is matched
against a model of its effects (`rm -rf` deletes, `curl -d` sends data out, `git
config core.hooksPath` persists), and known secret values (from `.env` and
credential-like variables) are masked in output that goes back to the agent.

Tests: `go test ./...`, then as a regular user `test/e2e.sh`, `test/policy-e2e.sh`,
`test/partial-e2e.sh`, `test/secret-e2e.sh`, `test/taint-e2e.sh`, `test/mirror-e2e.sh`,
`python3 test/ctrlc.py`, `test/claude-e2e.sh` and `test/codex-e2e.sh` (the real
Claude Code and Codex binaries against `test/mockapi`, a scripted mock of the
Messages and Responses APIs). With a real login, follow [docs/manual-test.md](docs/manual-test.md).

Each session keeps one SQLite database, `effects.db`: the effect log and the
outbox, with the history of every intent's status. Triggers make all of it
append-only, so `sqlite3` answers questions the review does not.

Not yet: secret handles (the agent sees a placeholder, airbag substitutes the
value at an allowed boundary), passing Codex's SQLite state through (transcripts
in `~/.codex/sessions` survive a discard, its thread index and memories do not). Tools that ignore the mirror settings cannot reach registries; `--allow HOST`
opens one directly. After a secret read the mirror serves only its cache, not
what a lockfile pins but nobody fetched yet.

## Threat model

airbag protects against accidents and casual exfiltration by an agent you let run
without prompts. It is not a VM: the kernel is shared, and whatever the agent reads
is still sent to the model API.

## License

Apache-2.0
