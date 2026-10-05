# Contributing to airbag

airbag is early: the core works and is tested on Linux, and the open question
is whether it is worth using on real work ([docs/evaluation.md](docs/evaluation.md)).
This page says how to build and test it, and where help changes the most.

## Build and test

You need Linux 5.12+ with unprivileged user namespaces (on Ubuntu 23.10+,
`airbag doctor` prints the AppArmor profile to install), Go 1.27.1 or newer
(the go.mod minimum: releases are built with a toolchain that has the current
standard-library security fixes) and, for the secret tests, a writable
`/dev/fuse`.

```console
$ go install ./cmd/airbag
$ airbag doctor
$ go test ./...
```

The end-to-end tests run real sessions with the `airbag` in your `PATH` (or
`AIRBAG=/path/to/airbag`), and must run as a regular user, not root:

```console
$ for t in test/e2e.sh test/*-e2e.sh; do sh "$t"; done
$ python3 test/ctrlc.py
```

One check needs a directory outside `$HOME`, `/tmp` and `/run` that the test
user can write, to place a host socket there: `sudo mkdir -m 1777
/var/lib/airbag-e2e` (or set `AIRBAG_E2E_HOSTDIR`); without it the check is
skipped.

WSL2 is checked by an informational CI job (`.github/workflows/wsl.yml`).

On macOS, `go build ./cmd/airbag` builds the prototype and `go test ./...` runs
the unit tests. Of the end-to-end tests, `test/e2e.sh` and
`test/agent-state-e2e.sh` check what the prototype promises there, and CI runs
them on every macOS runner; the others are Linux-only.

`sh test/check.sh` runs the static checks CI runs, with the same tool versions:
gofmt, `go mod tidy`, `go vet`, golangci-lint and govulncheck for Linux and
macOS, shellcheck and actionlint. `sh test/check.sh race` and
`sh test/check.sh fuzz` run the race and fuzz jobs; the versions are at the top
of the script.

`test/claude-e2e.sh` and `test/codex-e2e.sh` drive the real Claude Code and
Codex binaries (they skip when the binary is missing). The model is
`test/mockapi`, a scripted stand-in for the Anthropic Messages and OpenAI
Responses APIs, so no account or API key is needed. `demo/scenes.sh` records
the GIFs the same way.

`test/tty` runs sessions in a pseudo-terminal and checks the screen: a probe
for an agent reports what crosses airbag's terminal relay (size, resize, query
replies, paste, focus and mouse bytes, Ctrl-C), and the Claude Code and Codex
TUIs work through a task against `test/mockapi` (each skips when its CLI is
missing). The tests are behind the `e2e` build tag, so `go test ./...` leaves
them out; run them as a regular user with `go test -tags e2e ./test/tty/... -v`.
With `TTY_ARTIFACTS=dir` each test keeps its screens in `dir/<test>/`, as
`NAME.txt` and, when `freeze` is in `PATH`, `NAME.svg`, with an asciicast
recording, `session.cast` (`asciinema play` shows it); without it they go to a
temporary directory that is removed. `TTY_DIRECT=1` runs the same programs
without airbag, to check the harness itself where airbag cannot run. CI runs
them in `.github/workflows/tty.yml` and keeps the artifacts.

## Where to help

Open an issue before a large change, so we can agree on the shape first.
[docs/roadmap.md](docs/roadmap.md) lists what is deferred on purpose and what
would bring it back; please read it before starting on one of those.

**Run it on a Mac.** The macOS prototype ([docs/macos.md](docs/macos.md)) puts
one Seatbelt profile around the agent, uses an APFS clone as the branch and the
proxy on a localhost port. CI runs its unit tests, `test/e2e.sh` and the probe
in `cmd/airbag-macprobe` on hosted macOS runners, but nobody has used it on real
work yet. Run it with Claude Code or Codex and report what the page asks for.

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

Deferred on purpose, each with its reason in the roadmap: active syscall control
(seccomp user notification, eBPF; the static denylist is in), data flow labels per value, placeholders in
`.env` files, TLS termination for model APIs, more command models in
`internal/models`.

Smaller, self-contained tasks are labeled
[good first issue](https://github.com/getjump/airbag/labels/good%20first%20issue).

## Conventions

- Go with `gofmt`, `go vet` and the linters in `.golangci.yml`; a `//nolint`
  names the linter and says why. No new dependency without a reason in the PR.
- A change in behavior comes with a test: a unit test, and an e2e test under
  `test/` when it is about what a session does.
- Commit messages: an imperative summary line, then what changed and why.
- Update the README, or the page in `docs/` that covers it, when something
  user-visible changes.
- The maintainer's agent workflows, their labels and gates: [docs/agents.md](docs/agents.md).
- Security problems: please report them privately, as [SECURITY.md](SECURITY.md)
  says, not in a public issue.

## AI-assisted contributions

You are the author of what you submit, whatever tool helped: read every line,
run it, and be able to explain it without the tool. If a tool wrote a
substantial part, say so in the pull request (the template has a box for it)
or in an `Assisted-by: <tool>` commit trailer.

Issues and security reports are written and checked by a person. A bug report
needs steps you ran yourself. A security report needs a proof of concept that
works, and goes to a private advisory ([SECURITY.md](SECURITY.md)).

Agents that open issues, pull requests or comments on their own are not
accepted. Please work on `good first issue` items yourself, without an agent:
they are there for people new to the code. We may close what looks like
unreviewed tool output without review, and block those who keep sending it.

The maintainer's own agents are the exception: they label what they open
`agent-created` and follow [AGENTS.md](AGENTS.md); [docs/agents.md](docs/agents.md)
says how they are started and gated.
