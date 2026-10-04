# Roadmap and decisions

What is next, and what is deliberately not, with the reason. Two reviews on
2026-10-04 shaped it: a critique of where airbag reinvents existing tools, and
an external review that argued for narrowing the first release to "the agent
works apart, I see the consequences, I take the result onto a branch" and
testing the niche with users before the backlog ([evaluation.md](evaluation.md)).

## Next

1. **Run the macOS prototype on a real Mac** (docs/macos.md) and the probe in
   `cmd/airbag-macprobe`; decide on an NFS branch instead of the clone from the
   probe's N1 and N2 results.
2. **The evaluation** in [evaluation.md](evaluation.md): the comparison runs,
   then a narrow release to about ten developers.
3. **A first tagged release** once CI is green: `git tag v0.1.0` builds the
   binaries `install.sh` fetches.

## Deferred, and why

| Item | Why not now | What would bring it back |
|---|---|---|
| The `~/.claude.json` key-level write-back on macOS | The macOS prototype has no branch of `$HOME`, so the file stays writable in place and persists in full; the key-level write-back and review need a branch | A branch of `$HOME` on macOS (the NFS overlay in docs/macos.md) |
| A wider `~/.claude.json` write-back allowlist from an interactive run | The allowlist is built from a non-interactive `claude -p` run plus a few documented keys; an interactive session was not observable in CI, so keys it writes but `-p` does not stay in the branch (one extra review entry, never a silent write) | Observing an interactive session's config writes and adding the benign keys to the table |
| Per-value data flow labels (a file written from a secret is secret) | Session-wide labels already decide what matters (egress narrows after a read); per-value tracking through arbitrary programs is a research project | A real case where the session label is too coarse to be usable |
| An end-to-end guarantee that no secret reaches the model | Not true by design: the agent's own file tools read what they read, and model APIs stay reachable. The README says so; the e2e tests check what is promised (shell output is masked, egress elsewhere is refused) | TLS termination for model APIs, below |
| Placeholders in `.env` files (the agent reads a placeholder, the programs it starts the value) | Done for tokens bound to hosts (`credentials:`): the proxy puts the value in. A file has no host to bind to, and telling the agent's reads from its programs' is per-process tracking | A real case where an `.env` value must be used without the session being labelled |
| TLS termination for model APIs | Every agent request would pass through it, and the agents keep their own trust stores; what it would add is pinning the agent's own key | Users who need the agent's key pinned, or secrets kept out of the model's context |
| Syscall control (seccomp user notification, eBPF) | The proxy, FUSE and the sandbox are the boundary; observing every syscall is a large project with known time-of-check limits | A threat the current boundary misses in practice |
| Approvals beyond `ask` and `airbag approve` (events stream, `on_ask`, standing approvals, `watch`) | Blocking approval is a commodity; the outbox is what is airbag's. The work is kept on the `wip/approvals` branch | Users asking to approve from elsewhere (phone, chat) |
| An `airbag defer -- CMD` for the agent to queue any command itself | A queue of whatever the agent picks is approving commands, not outcomes, and it gives injected instructions a way to stage commands for the host. `defer:` keeps the choice of what may wait with the user | Agents that need to hold actions no `defer:` entry foresees |
| Showing a deferred command's result to the agent | It runs at apply, when the session is over; running it earlier would put it before the review | A workflow where the agent continues after an approved action |
| Savepoints per tool call | `rollback` undoes an apply and `--session` iterates; per-step savepoints would be git trees per step, after the evaluation shows they are wanted | Reviews where one bad step spoils a long run |
| A hash-chained, signed effect log | Worth it only when a third party reads the log; locally the user can rewrite their own files. If built: `golang.org/x/mod/sumdb/tlog` | A team or CI consuming session logs |
| An MCP server broker (credentials outside the sandbox) | Tool permissions are the agent's job, and a server in the sandbox that calls its API over HTTPS can take its token through `credentials:` like any tool | MCP servers whose credential is not an HTTP token |
| A NixOS VM test matrix (kernels, no user namespaces, no FUSE) | Needs KVM in CI; the flake's unit checks and the CI e2e run cover the main path | A bug that only one kernel shows |
| A "only what is declared is visible" mode (devShell closure) | Optional hardening; after the evaluation | Users who want tools hidden, not just credentials |
| More command models, a model language | Models are predictions for review, not the boundary; frozen while observation is what matters | — |
