# Support and versions

Which systems airbag runs on, how its versions are numbered, and what a
release keeps from one version to the next.

## Platforms

| Tier | Platforms | What it means |
|---|---|---|
| 1 | Linux on amd64 and arm64, kernel 5.12 or later with unprivileged user namespaces (on Ubuntu 23.10 and later, the AppArmor profile `airbag doctor` prints) | Release binaries. The unit and end-to-end tests pass before each release, and a bug here blocks one |
| 2 | macOS 13 or later on Apple silicon and Intel: the native prototype | Release binaries and unit tests. It has not run end to end on a real Mac yet; its limits are in [macos.md](macos.md) |
| 3 | Everything else Go builds airbag for, and NixOS through the flake | Built from source on a best-effort basis, with no tests promised; fixes are welcome |

The release binaries are static (`CGO_ENABLED=0`) and built with the Go
version that `go.mod` names (1.27.1 now). A source build needs that version or
newer. `airbag doctor` checks what the machine is missing.

airbag runs any agent, and gives Claude Code and Codex hooks so the review
shows which tool call changed which file. `test/claude-e2e.sh` and
`test/codex-e2e.sh` drive the real CLIs against a mock API. A newer agent
release can write state that airbag does not know yet. The review shows it as
`unknown key(s)`, which needs a decision; such state never passes silently.

## Versions

airbag uses [Semantic Versioning](https://semver.org/) and is at 0.x, where
the rules are:

- A minor release (0.1 to 0.2) may break the public surface below. Each break
  is listed in [CHANGELOG.md](../CHANGELOG.md) under Changed or Removed. Where
  it is feasible, the old form keeps working for one minor release first, with
  a warning.
- A patch release (0.1.0 to 0.1.1) fixes bugs, security bugs included, and
  breaks nothing public.
- Fixes go to the latest minor release only.
- A pre-release (`v0.2.0-rc.1`) tests the release itself. `releases/latest`
  and the default of `install.sh` skip it, and `go install ...@latest` takes
  it only while there is no release.
- A published release is never replaced, since releases are immutable. A bad
  one is marked `[YANKED]` in the changelog and retracted in `go.mod`, and a
  patch release follows.

From 1.0 on, a break needs a major release.

## Public surface

These are what the version rules above cover:

- The command line: the commands, their flags and what they mean.
- `airbag.yaml`, in a repository and in `~/.config/airbag/airbag.yaml`: the
  keys and what they mean.
- The JSON that `airbag review --json` prints, schema `airbag.review/v1`.
  Within v1, fields are only added. Removing or changing one takes a new schema
  name.

Anything else may change in any release: the text output of `review` and of
the other commands, which is written for people; the session directory and its
`effects.db`; the hooks and managed settings that airbag gives agents; what the
command models predict; and the Go packages, which are all under `internal/`.
