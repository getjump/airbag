# Contributing to airbag

airbag is early: the core works and is tested on Linux, and the open question
is whether it is worth using on real work ([docs/evaluation.md](docs/evaluation.md)).
This page says how to build and test it, and where help changes the most.

## Build and test

You need Linux 5.12+ with unprivileged user namespaces (on Ubuntu 23.10+,
`airbag doctor` prints the AppArmor profile to install), Go 1.24 and, for the
secret tests, a writable `/dev/fuse`.

```console
$ go install ./cmd/airbag
$ airbag doctor
$ go test ./...
```

The end-to-end tests run real sessions with the `airbag` in your `PATH` (or
`AIRBAG=/path/to/airbag`), and must run as a regular user, not root:

```console
$ for t in test/*-e2e.sh; do sh "$t"; done
$ python3 test/ctrlc.py
```

One check needs a directory outside `$HOME`, `/tmp` and `/run` that the test
user can write, to place a host socket there: `sudo mkdir -m 1777
/var/lib/airbag-e2e` (or set `AIRBAG_E2E_HOSTDIR`); without it the check is
skipped.

On macOS, `go build ./cmd/airbag` builds the prototype and `go test ./...` runs
the unit tests; the end-to-end tests are Linux-only.

`test/claude-e2e.sh` and `test/codex-e2e.sh` drive the real Claude Code and
Codex binaries (they skip when the binary is missing). The model is
`test/mockapi`, a scripted stand-in for the Anthropic Messages and OpenAI
Responses APIs, so no account or API key is needed. `demo/scenes.sh` records
the GIFs the same way.

## Where to help

Open an issue before a large change, so we can agree on the shape first.
[docs/roadmap.md](docs/roadmap.md) lists what is deferred on purpose and what
would bring it back; please read it before starting on one of those.

**Run it on a Mac.** The macOS prototype ([docs/macos.md](docs/macos.md)) puts
one Seatbelt profile around the agent, uses an APFS clone as the branch and the
proxy on a localhost port. It is built and unit-tested on Linux and has not run
on a Mac yet. Run it with Claude Code or Codex and report what the page asks
for. The probe in `cmd/airbag-macprobe` decides whether the workspace branch
moves to NFS on localhost, as AgentFS does.

**Use it on real work.** [docs/evaluation.md](docs/evaluation.md) is the plan
for telling whether airbag is worth using against a worktree with the agent's
own sandbox, nono and Code Airlock. Runs, and issues about review noise, false
flags and tools that break in the sandbox, are the most useful input now.

**More agents.** Claude Code and Codex get hooks, so the review shows which
tool call changed what. Gemini CLI, Aider, OpenCode and others run in the
sandbox but without that attribution.

**More lock files.** After a secret read the mirror serves only its cache and
what the workspace's lock files pin. `internal/mirror/pins.go` reads
`package-lock.json`, `yarn.lock`, `go.sum` and `uv.lock`; `pnpm-lock.yaml`,
`poetry.lock` and hashed requirements files are missing.

**bubblewrap underneath.** airbag sets up namespaces itself in Go.
[docs/bwrap-backend.md](docs/bwrap-backend.md) has the evaluation: not with
bubblewrap 0.9 (no overlay), worth measuring as a hybrid once 0.11+ is common.
Its `--disable-userns` idea is in airbag as `--strict`.

Deferred on purpose, each with its reason in the roadmap: syscall-level control
(seccomp user notification, eBPF), data flow labels per value, placeholders in
`.env` files, TLS termination for model APIs, more command models in
`internal/models`.

Smaller, self-contained tasks are labeled
[good first issue](https://github.com/getjump/airbag/labels/good%20first%20issue).

## Conventions

- Go with `gofmt` and `go vet`; no new dependency without a reason in the PR.
- A change in behavior comes with a test: a unit test, and an e2e test under
  `test/` when it is about what a session does.
- Commit messages: an imperative summary line, then what changed and why.
- Update the README when something user-visible changes.
- Security problems: please report them privately through a GitHub security
  advisory, not a public issue.
