# Status in detail

The README's [Status](../README.md#status) lists what works. This page says how
the agents' hooks and the shell models work, how airbag is tested, and what is
not done yet.

Claude Code gets airbag's hooks as read-only managed settings, Codex as a
read-only `/etc/codex/requirements.toml` (unless the host has its own), so the
review shows which tool call changed which file. Codex's own SQLite state folds
into one review line.
`bash` and `sh` are shimmed: each `-c` script is parsed, every command is matched
against a model of its effects (`rm -rf` deletes, `curl -d` sends data out, `git
config core.hooksPath` persists), and known secret values (from `.env` and
credential-like variables) are masked in its output. The models are predictions
for review and early refusals; scripts and programs they do not cover are
`opaque`, and the boundary for those is the sandbox, the proxy and FUSE.

Tests: `go test ./...`, then as a regular user every `test/*e2e.sh` and
`python3 test/ctrlc.py` (CI runs them on each push); `test/claude-e2e.sh` and
`test/codex-e2e.sh` drive the real Claude Code and Codex binaries against
`test/mockapi`, a scripted mock of the Messages and Responses APIs. With a real login, follow [manual-test.md](manual-test.md).

Each session keeps one SQLite database, `effects.db`: the effect log and the
outbox, with the history of every intent's status. Triggers make all of it
append-only, so `sqlite3` answers questions the review does not.

Not yet: passing Codex's SQLite state through (transcripts in `~/.codex/sessions`
survive a discard, its thread index and memories do not), and pins from
`pnpm-lock.yaml`, `poetry.lock` and hashed requirements files for the mirror after a
secret read. Tools that ignore the mirror settings cannot reach registries;
`--allow HOST` opens one directly.

Deliberately left for later, each with the reason and what would bring it back:
[roadmap.md](roadmap.md).
