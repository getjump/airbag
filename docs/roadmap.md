# Roadmap and decisions

What is next, and what is deliberately not, with the reason. Two reviews on
2026-10-04 shaped it: a critique of where airbag reinvents existing tools, and
an external review that argued for narrowing the first release to "the agent
works apart, I see the consequences, I take the result onto a branch" and
testing the niche with users before the backlog ([evaluation.md](evaluation.md)).
Two experiments on stronger execution backends and on AgentFS as the branch's
storage are summed up in [experiments.md](experiments.md).

## Next

1. **Use the macOS prototype on real work** (docs/macos.md) with Claude Code
   and Codex. CI runs its unit tests, `test/e2e.sh` and `cmd/airbag-macprobe` on
   hosted macOS, and Claude Code's `!` command and Bash tool against a mock
   API. A real Claude account login remains unvalidated; Keychain is hidden,
   so the current profile needs an API key or OAuth token in the environment.
   The probe's N2 and N3 failed there, so the clone stays the branch.
2. **The evaluation** in [evaluation.md](evaluation.md): the comparison runs,
   then a narrow release to about ten developers.
3. **A first tagged release** once CI is green: `git tag v0.1.0` builds the
   binaries `install.sh` fetches.

## Deferred, and why

| Item | Why not now | What would bring it back |
|---|---|---|
| `~/.claude.json` review on macOS | The macOS prototype has no branch of `$HOME`, so the file stays writable in place and persists in full; reviewing it by key needs a branch | A branch of `$HOME` on macOS (the NFS overlay in docs/macos.md) |
| Agent state on macOS kept in the session | Seatbelt denies paths, not files, so protecting memory and settings by path needs another rule for each layout of links and hard links (a protected file with a second name in `~/.claude.json` or a temporary directory is still writable); the prototype stops at the rules it has | A real-Mac run (step 1 above), then the agent's state handed to it as a copy in the session (an APFS clone, through `CLAUDE_CONFIG_DIR` and `CODEX_HOME` if the CLIs honour them in full) with the real `$HOME` read-only, reviewed and applied like the Linux branch |
| Checking the transcripts and login that pass through | This workspace's transcripts and the login files pass through so `claude --resume` and the login survive a discard; airbag does not check what the agent writes there, so resuming such a transcript outside airbag, or a login the agent changed, carries sandbox-written state into a host session ([What the agent gets](agent.md#sessions-and-agent-state), "Its own state") | Existing transcripts read-only to the agent and only the files this session created carried across a discard (airbag's hooks already see `transcript_path`); a login change detected as a change of account |
| More `~/.claude.json` benign keys | The allowlist covers what Claude Code was observed to write on its own: a `claude -p` run, an interactive first run (onboarding, API-key, folder-trust and bypass-mode dialogs) and an ordinary interactive run after it. Keys written in situations not observed (a login to a real account, `/config` changes, plugin installs) show in review as `unknown key(s)`: an entry that asks for a decision, never a silent pass | Observing those situations and listing their benign keys in the table |
| Writing Claude Code's counters to the real `~/.claude.json` before apply | Copying benign keys back at session end means a three-way merge with a file the host CLI rewrites at the same time, and an atomic compare-and-swap that keeps its owner, mode and extended attributes; that machinery kept growing review findings. The counters reach the real file with apply, and a discard drops them | A host CLI that keeps its counters in a file apart from its settings |
| Per-value data flow labels (a file written from a secret is secret) | Session-wide labels already decide what matters (egress narrows after a read); per-value tracking through arbitrary programs is a research project | A real case where the session label is too coarse to be usable |
| An end-to-end guarantee that no secret reaches the model | Not true by design: the agent's own file tools read what they read, and model APIs stay reachable. The README says so; the e2e tests check what is promised (shell output is masked, egress elsewhere is refused) | TLS termination for model APIs, below |
| Placeholders in `.env` files (the agent reads a placeholder, the programs it starts the value) | Done for tokens bound to hosts (`credentials:`): the proxy puts the value in. A file has no host to bind to, and telling the agent's reads from its programs' is per-process tracking | A real case where an `.env` value must be used without the session being labelled |
| TLS termination for model APIs | Every agent request would pass through it, and the agents keep their own trust stores; what it would add is pinning the agent's own key | Users who need the agent's key pinned, or secrets kept out of the model's context |
| Active syscall control (seccomp user notification, eBPF) | A static seccomp denylist now narrows the kernel surface (the hardening list in [What the agent gets](agent.md#terminal-and-kernel): io_uring, bpf, perf_event_open, the keyring, kexec, modules, odd socket families, and more); *observing* or *gating* every syscall live is a larger project with known time-of-check limits, and the proxy, FUSE and the sandbox stay the boundary | A threat the current boundary misses in practice |
| Approvals beyond `ask` and `airbag approve` (events stream, `on_ask`, standing approvals, `watch`) | Blocking approval is a commodity; the outbox is what is airbag's. The work is kept on the `wip/approvals` branch | Users asking to approve from elsewhere (phone, chat) |
| An `airbag defer -- CMD` for the agent to queue any command itself | A queue of whatever the agent picks is approving commands, not outcomes, and it gives injected instructions a way to stage commands for the host. `defer:` keeps the choice of what may wait with the user | Agents that need to hold actions no `defer:` entry foresees |
| Showing a deferred command's result to the agent | It runs at apply, when the session is over; running it earlier would put it before the review | A workflow where the agent continues after an approved action |
| Savepoints per tool call | `rollback` undoes an apply and `--session` iterates; per-step savepoints would be git trees per step, after the evaluation shows they are wanted | Reviews where one bad step spoils a long run |
| A hash-chained, signed effect log | Worth it only when a third party reads the log; locally the user can rewrite their own files. If built: `golang.org/x/mod/sumdb/tlog` | A team or CI consuming session logs |
| An MCP server broker (credentials outside the sandbox) | Tool permissions are the agent's job, and a server in the sandbox that calls its API over HTTPS can take its token through `credentials:` like any tool | MCP servers whose credential is not an HTTP token |
| A NixOS VM test matrix (kernels, no user namespaces, no FUSE) | Needs KVM in CI; the flake's unit checks and the CI e2e run cover the main path | A bug that only one kernel shows |
| A "only what is declared is visible" mode (devShell closure) | Optional hardening; after the evaluation | Users who want tools hidden, not just credentials |
| More command models, a model language | Models are predictions for review, not the boundary; frozen while observation is what matters | — |
