# Manual check with a real agent login

Automated tests drive the real Claude Code binary against `test/mockapi`.
What they cannot cover is a real login and a real model. Run this on your
own Linux machine before a release.

## Before

1. `airbag doctor` passes. On Ubuntu 23.10+ install the AppArmor profile it prints.
2. Log in to Claude Code outside airbag once (`claude`, then `/login`). The
   OAuth callback listens on localhost, which the sandbox cannot reach, so the
   first login happens outside. Inside, `~/.claude/.credentials.json` and
   `~/.claude.json` pass through, so token refreshes are kept.

## Session

```console
$ cd ~/some-project
$ airbag run -- claude --dangerously-skip-permissions
```

Ask the agent to:

- [ ] edit two files and add one, then run the tests;
- [ ] `git commit` and `git push`: the push answers `queued as intent i-N`;
- [ ] with `defer: [gh pr create]` in `airbag.yaml`, commit the result and queue a
  PR with explicit repo/base/head/title/body ([workflow](typed-pr-outbox.md));
  it answers `queued as intent i-N` and a JSON queued result, while `gh pr list` runs (and fails
  without a token);
- [ ] fetch a page from a host that is not allowlisted: it gets `403 ... denied by policy`;
- [ ] read `~/.ssh/id_*`: nothing is there;
- [ ] with a `credentials:` entry for GitHub in `~/.config/airbag/airbag.yaml`
  (`source: command:gh auth token`, `env: [GH_TOKEN]`), `gh pr list` works,
  `echo $GH_TOKEN` shows a placeholder, and review lists the requests.

Then check the terminal:

- [ ] Ctrl-C interrupts the agent's current action, a second Ctrl-C or `/exit` quits;
- [ ] Ctrl-Z stops the agent and returns to the shell, `fg` brings it back;
- [ ] resizing the window redraws the agent's UI;
- [ ] after exit airbag prints `session s-… ended`.

## Review

```console
$ airbag review
$ airbag diff
```

- [ ] Steps list the agent's tool calls with the files each one changed;
- [ ] Network shows `api.anthropic.com` and any denied hosts;
- [ ] the real files are unchanged (`git status` is clean);
- [ ] `airbag review --attention` lists the waiting push and any flagged change;
- [ ] `airbag review --json | jq -r .schema` prints `airbag.review/v1`.

## Iterate, then take the result

- [ ] `airbag run --session last -- claude --continue` continues on the same
  branch: the agent sees its earlier edits, and review numbers the steps on.

Then one of:

- [ ] `airbag apply`: the files land, the push runs after confirmation, then
  the typed PR preview asks on its own and publishes with your host credentials
  only when both commits match; then
  `airbag rollback` puts the files back as they were and the changes back into
  the session (`airbag review` shows them again);
- [ ] `airbag apply --branch try-1`: `git log try-1` has the agent's commits and
  one commit with what it left uncommitted; `git status` and the current branch
  are unchanged, and the queued push is reported for you to run yourself;
- [ ] `airbag discard`: the session's branch is gone, the real files untouched.

## Resume

- [ ] `airbag run -- claude --resume` in the same project lists the earlier
  conversation. Transcripts pass through even when the branch was discarded,
  so the conversation may mention edits that no longer exist.

## Codex

```console
$ airbag run -- codex --dangerously-bypass-approvals-and-sandbox
```

Run the same session tasks, then:

- [ ] Steps list Codex's commands (Codex reports them as `Bash`);
- [ ] a command an `airbag.yaml` rule denies is refused before it runs;
- [ ] Network shows `chatgpt.com` or `api.openai.com`;
- [ ] Home folds Codex's state into one `~/.codex/… (agent state)` line;
- [ ] `airbag run -- codex resume` lists the earlier session.
- [ ] `airbag run --strict -- codex` without the bypass flag prints the warning
  that Codex's own sandbox cannot start.

Report any host the agent needed that airbag denied; `--allow HOST` adds it.
