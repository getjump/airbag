# How airbag compares

The [README](../README.md#how-it-compares) compares airbag with the agents'
built-in sandboxes, dev containers and VMs, and walks through an example. This
page has the rest.

Tools that also let you decide after the run, at least for files:

| | Files | Network | Pushes, publishes, API calls | Secrets |
|---|---|---|---|---|
| [nono](https://github.com/nolabs-ai/nono) `--rollback` | writes land in place; snapshot before, diff after, restore what you pick | blocked by default, L7 proxy | asked live by its supervisor | stand-in credential, real one injected by the proxy |
| [try](https://github.com/binpash/try) | overlayfs branch of one command, commit or not | unrestricted | run as they happen | not handled |
| [AgentFS](https://github.com/tursodatabase/agentfs) | copy-on-write branch of the working directory (SQLite delta), `agentfs diff`; no apply command | not controlled | run as they happen | not handled |
| [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) in clone mode, or [Code Airlock](https://github.com/Trivo25/code-airlock) on top of it | microVM with a private clone, host repo read-only; review and merge with `git fetch`, `git diff` | allowlist through a proxy | not held | proxy injects credentials, values stay outside the VM |
| Claude Code sandbox and checkpoints | writes in the workspace, `/rewind` restores the agent's own file edits, not Bash's | allowlist through a proxy, asks for new domains | auto mode's classifier blocks some | denied or masked behind a proxy |
| airbag | copy-on-write branch of the workspace and `$HOME`; persistence flagged; apply all, part or none, or onto a git branch; `rollback` | allowlist, every host logged, mirror, cut on a secret read | `git push` and the commands `defer:` names (`gh pr create`) queued in the outbox, run after review; other publishing fails at the read-only mirror; calls to allowed hosts happen when made, a rule can `ask` | hidden; a read labels the session and narrows egress; tokens you bind reach the agent as placeholders, the proxy puts the value in |

What airbag adds is around the branch rather than the branch itself: the outbox
that holds `git push` and the commands you name until review, the `$HOME` branch with persistence called out,
a label that follows a secret read through the rest of the session, and one review
that works the same for any agent, on your own toolchain without a VM. The result
goes onto your files or onto a git branch, and an apply can be rolled back.
Whether that beats a VM clone or nono for a given team is a matter of measuring,
not of this table. Airbag also offers opt-in [runtime filesystem and exec
policies](runtime-policy.md) on Linux, while keeping outcome review as its
main workflow. Tools that govern more effects at runtime, such as
[agentsh](https://github.com/canyonroad/agentsh) (file, process and network policy
with approvals, an LLM proxy with DLP), cover additional runtime controls and
model-request content. Airbag's network boundary remains its forced proxy; it
does not currently offer LLM DLP. (As of
October 2026, from each project's documentation.)

## bubblewrap underneath

airbag sets up its namespaces itself. Could it run on bubblewrap underneath?
Not yet: bubblewrap 0.9, which Ubuntu 24.04 ships, cannot make the overlay the
branch needs, and FUSE, the proxy bridge and the agent settings would stay
airbag's anyway. See [bwrap-backend.md](bwrap-backend.md).
