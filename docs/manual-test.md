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
- [ ] fetch a page from a host that is not allowlisted: it gets `403 ... denied by policy`;
- [ ] read `~/.ssh/id_*`: nothing is there.

Then check the terminal:

- [ ] Ctrl-C interrupts the agent's current action, a second Ctrl-C or `/exit` quits;
- [ ] resizing the window redraws the agent's UI;
- [ ] after exit airbag prints `session s-… ended`.

## Review

```console
$ airbag review
$ airbag diff
```

- [ ] Steps list the agent's tool calls with the files each one changed;
- [ ] Network shows `api.anthropic.com` and any denied hosts;
- [ ] the real files are unchanged (`git status` is clean).

Then either `airbag apply` (the files land, the push runs after confirmation)
or `airbag discard`.

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
- [ ] `airbag run -- codex` without the bypass flag prints the warning that
  Codex's own sandbox cannot start; with `--allow-userns` it starts.

Report any host the agent needed that airbag denied; `--allow HOST` adds it.
