# Changelog

All notable changes to airbag are listed here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with the 0.x
rules in [docs/support.md](docs/support.md).

A release takes its notes from its section here: `vX.Y.Z` from `## [X.Y.Z]`,
a pre-release such as `v0.1.0-rc.1` from `## [Unreleased]`.

## [Unreleased]

Nothing is released yet; this is what the first release holds.

### Added

- `airbag run` runs a coding agent in a copy-on-write branch of the workspace
  and `$HOME`, with the rest of the host read-only. `--session` runs again on a
  stopped session's branch, `--no-home` leaves `$HOME` read-only, and
  `--strict` keeps the agent from creating user namespaces.
- One way out: the agent reaches the network only through airbag's proxy, with
  an allowlist, checks of the addresses it connects to, and every host logged.
  Go, npm, pip, uv and yarn go through a package mirror; `tcp://` entries
  forward local services.
- An outbox: `git push` and the commands `defer:` names wait until review and
  run after `apply`.
- Secrets: credential stores and credential-like environment variables are
  hidden; `.env` and other secret files are served through FUSE, and a read
  labels the session and narrows egress; known values are masked in shell
  output; tokens bound to hosts reach the agent as placeholders that the proxy
  fills in.
- A seccomp filter that removes kernel surface an agent has no use for, and a
  pseudo-terminal of the agent's own.
- `bash` and `sh` shims that predict each command's effects for review.
- Policies: CEL rules over effects in `airbag.yaml`, with `ask` verdicts and
  `airbag approve`.
- `airbag review` (text, `--attention`, and `--json` with the
  `airbag.review/v1` schema) flags persistence such as a new line in
  `~/.bashrc`; `airbag diff`, `log` and `ls`.
- `airbag apply`, all or nothing after a conflict check, in part (`-i`,
  `--only`) or onto a git branch (`--branch`); `airbag rollback` undoes the
  last apply, `airbag discard` throws the branch away.
- Claude Code and Codex get airbag's hooks as read-only managed settings, so
  review shows which tool call changed which file.
- `airbag doctor` checks that the machine can run airbag.
- A macOS prototype: Seatbelt around the agent and an APFS clone as the
  branch, not yet run on a real Mac ([docs/macos.md](docs/macos.md)).
- `install.sh`, `go install` and a Nix flake; `airbag version` reports the
  module version for `go install ...@vX`.
- Releases built by GoReleaser and published immutable: archives with
  `LICENSE` and `README.md`, an SBOM per archive, `checksums.txt` signed with
  Sigstore, and GitHub build provenance. [docs/verify.md](docs/verify.md)
  shows how to check them and how to rebuild the binaries.
- `install.sh` is a release asset: it checks with cosign or a logged-in `gh`
  that the release workflow built the archive, when either is installed, and
  stops if that check fails; it always checks the SHA-256, and says so when
  that was the only check. `AIRBAG_VERIFY=require` refuses to install without
  cosign or `gh`.
- Public Go packages for embedding parts of airbag in another agent runtime:
  `operation`, `policy`, `audit`, `outbox`, `githubpr`, `creds` and `proxy`,
  the same code the CLI runs; not a stable API yet
  ([docs/composition.md](docs/composition.md)).

[Unreleased]: https://github.com/getjump/airbag/commits/main
