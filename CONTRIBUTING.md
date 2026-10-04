# Contributing to airbag

airbag is early: the core works and is tested, but most of the interesting
design is still open. This page says how to build and test it, and where help
changes the most.

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

`test/claude-e2e.sh` and `test/codex-e2e.sh` drive the real Claude Code and
Codex binaries (they skip when the binary is missing). The model is
`test/mockapi`, a scripted stand-in for the Anthropic Messages and OpenAI
Responses APIs, so no account or API key is needed. `demo/scenes.sh` records
the GIFs the same way.

## Where to help

Each area below is a real gap. Open an issue before a large change, so we can
agree on the shape first.

**A language for effects.** Commands are modeled in Go in `internal/models`:
`rm -rf x` deletes `x`, `curl -d @f url` sends `f` to `url`. The goal is to
describe effects as data, close to function signatures in a functional
language, and let users add models without rebuilding airbag. Starlark is the
leading candidate. A first step: port three existing models and keep their
tests passing.

**macOS.** There are no Linux namespaces there. [docs/macos.md](docs/macos.md)
covers running in a Linux VM today, what still needs checking there, and a
native design: Seatbelt for the network and credentials, APFS clones for the
workspace branch, FUSE-T or FSKit for secret tracking.

**Syscall-level control.** The shell shim sees `bash -c` scripts, not what a
Python program does inside. A seccomp user-notification supervisor
(`openat`, `connect`, `execve`) would give the same control over any language
and binary without root. Use `SECCOMP_IOCTL_NOTIF_ADDFD` for allowed opens
rather than letting the call continue, to avoid time-of-check races.

**Labels and data flow.** `internal/taint` labels the whole session (`secret`,
`untrusted`) and CEL rules read `session.labels`. Next: follow labels through
files and processes (a file written from a secret is itself secret), add
sources of `untrusted` input, and an end-to-end test that no secret value ever
reaches a model request.

**Model API traffic.** The proxy cannot see inside TLS to model APIs, so it
cannot tell the agent's key from another one. Terminating TLS for those hosts
inside the sandbox would allow that check, and secret handles: the agent sees
a placeholder, airbag substitutes the value at an allowed boundary.

**bubblewrap underneath.** airbag sets up namespaces itself in Go.
[docs/bwrap-backend.md](docs/bwrap-backend.md) has the evaluation: not with
bubblewrap 0.9 (no overlay), worth measuring as a hybrid once 0.10+ is common.
Meanwhile its `--disable-userns` idea can move into airbag now.

**More agents.** Claude Code and Codex get hooks, so the review shows which
tool call changed what. Gemini CLI, Aider, OpenCode and others run in the
sandbox but without that attribution.

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
