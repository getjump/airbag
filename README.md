# airbag

**Approve outcomes, not commands.** Run your coding agent without permission
prompts inside a copy-on-write branch of your machine. Review one diff at the end,
then apply it or throw it away.

```console
$ airbag run -- claude --dangerously-skip-permissions
$ airbag review
$ airbag apply        # or: airbag discard
```

## What the agent gets

- **A branch of the world.** The workspace and `$HOME` are overlayfs branches; the
  rest of the host is read-only. Nothing the agent writes reaches your files before
  `airbag apply`.
- **One way out.** The sandbox has no network interface besides loopback and no
  DNS. Traffic leaves only through airbag's proxy, which allows model APIs and
  package registries (`--allow HOST` adds more) and logs every host.
- **An outbox.** `git push` returns `queued` and runs on the host after you approve
  it. Pushing around the shim fails at the proxy.
- **No credentials.** `~/.ssh`, `~/.aws`, `gh`, `docker`, `kube` and similar are
  hidden. Host sockets (docker.sock, D-Bus, ssh-agent, X11, Wayland) are out of
  reach: `/run`, `/tmp` and `/dev/shm` are private.
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
while the agent worked.

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
read-only managed settings, so the review shows which tool call changed which file.

Tests: `go test ./...`, then as a regular user `test/e2e.sh`, `python3 test/ctrlc.py`
and `test/claude-e2e.sh` (the real Claude Code binary against a scripted mock of the
Messages API). With a real login, follow [docs/manual-test.md](docs/manual-test.md).

Not yet: the shell shim with command models, CEL policies in `airbag.yaml`, a local
registry mirror, secret handles and output masking, an interactive review with
partial apply, Codex hooks.

## Threat model

airbag protects against accidents and casual exfiltration by an agent you let run
without prompts. It is not a VM: the kernel is shared, and whatever the agent reads
is still sent to the model API.

## License

Apache-2.0
