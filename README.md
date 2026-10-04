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
- **Watched secrets.** The workspace's `.env` files are served read-only through
  FUSE. The first read by anything but airbag taints the session: commands that
  send data out are refused, only model APIs stay reachable, and the mirror
  serves only what it has cached. The read returns only after airbag has recorded the taint and closed
  connections opened earlier to other hosts. Output going back to the agent has
  known secret values masked.
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

Verdicts are `allow`, `deny` and `ask`; a deny anywhere wins. An `ask` blocks the
command and tells the agent to have you run `airbag approve a-N`; after that the
retry passes. For Claude Code the answer arrives through a PreToolUse hook, before
the command runs; Codex gets the same through its hooks. The repository's file is read from the real workspace, so the
agent cannot loosen its own rules, and a change to it shows up in review as
`persist`.

## Install

```console
$ go install github.com/getjump/airbag/cmd/airbag@latest
$ airbag doctor
```

One static binary, no daemon, no Docker. Needs Linux 5.12+ with unprivileged user
namespaces. On Ubuntu 23.10+ AppArmor restricts them; `airbag doctor` prints the
one-time profile to install. macOS is not supported yet (use a Linux VM).

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
`test/partial-e2e.sh`, `test/secret-e2e.sh`, `test/mirror-e2e.sh`,
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
