# airbag on macOS

airbag is built on Linux namespaces, overlayfs and FUSE; macOS has none of
them. This page records how the agents and agent sandboxes that run natively
on macOS do it (as of October 2026), the native design that follows for
airbag, the prototype of it, and the Linux VM setup, which stays the way to use
airbag on a Mac for real work until the prototype has been used on one. The release binaries need macOS 13
or later (the minimum of the Go release they are built with).

## How others sandbox agents on macOS

The agents' own sandboxes all run natively, on Seatbelt (`sandbox-exec`).
VM-based options (Docker Sandboxes, Apple's `container`) exist as separate
tools; none of the agents uses one by default.

| Tool | Mechanism on macOS | Notes |
|---|---|---|
| Claude Code ([sandbox-runtime](https://github.com/anthropics/sandbox-runtime)) | `sandbox-exec` with Seatbelt profiles generated per run | The profile allows outbound traffic only to one localhost port, where HTTP and SOCKS proxies filter domains. Reads the system's sandbox violation log for live alerts. Go tools that verify TLS through a filtering proxy need access to `trustd`, which the project flags as weaker isolation |
| [Codex](https://learn.chatgpt.com/docs/sandboxing) | Seatbelt | `workspace-write` mode: writes only inside the workspace, network on or off |
| [Gemini CLI](https://google-gemini.github.io/gemini-cli/docs/cli/sandbox.html) | Seatbelt profiles: permissive or restrictive, network open, closed or proxied | Docker and Podman as alternatives |
| [Cursor](https://cursor.com/blog/agent-sandboxing) | Seatbelt, profile generated from workspace and admin settings | Evaluated App Sandbox (every binary the agent runs would need signing), containers (Linux binaries only), VMs (startup latency, memory) and chose Seatbelt. Denies writes to `.vscode`, `.cursor`, `.git/config`, `.git/hooks`. A blocked command reports which rule blocked it, and agents stopped 40% less often |
| [Agent Safehouse](https://agent-safehouse.dev/) | Wraps the whole agent in `sandbox-exec`, deny-first | One Bash script; `safehouse claude --dangerously-skip-permissions` |
| [nono](https://github.com/lukehinds/nono) | Seatbelt (Landlock on Linux) | Tools get a stand-in credential; a proxy outside the sandbox injects the real one into requests to approved APIs |
| [AgentFS](https://turso.tech/blog/agentfs-overlay) | Copy-on-write overlay served by a **localhost NFS server**, mounted with the built-in `mount_nfs`, plus `sandbox-exec` | No kernel extension. Upper layer in SQLite; `agentfs diff` shows changes. On Linux the same overlay goes through FUSE and namespaces |

Two of these overlap with airbag's plans: AgentFS has the copy-on-write branch,
nono has credentials injected outside the sandbox. None combines the branch,
the review and outbox, and effect policies.

Seatbelt's known costs: `sandbox-exec` has been deprecated since 2016, though
Chrome and Apple's own apps still rely on Seatbelt; profiles are subtle, and
public escapes from agent sandbox profiles have been reported; it cannot filter
by host name, so network control goes through a local proxy. App Sandbox,
Endpoint Security and Network Extension need Apple signing or entitlements and
do not suit an open-source command-line tool.

## Native design for airbag

| airbag on Linux | On macOS | Precedent |
|---|---|---|
| Namespaces around the agent | One deny-first Seatbelt profile around the whole agent process tree | Safehouse, nono, sandbox-runtime |
| Network namespace, only the proxy | Outbound allowed only to airbag's proxy port on localhost, plus ports from `tcp://` rules | sandbox-runtime |
| overlayfs branch of the workspace | airbag serves the overlay over NFS on localhost (lower: the real workspace, read-only; upper: the session directory) and mounts it with `mount_nfs`; the agent works in the mount | AgentFS |
| Branch of `$HOME` | No branch: `$HOME` read-only, agent state passes through, caches (`npm`, `go`, `pip`) redirected into the session by environment variables | AgentFS's default writable directories |
| Secret files through FUSE | The same NFS server serves them: a read taints the session. The reader's pid is not visible over NFS, so attribution is per session. Credentials outside the workspace are denied by the profile | |
| Blocked operations | Read the Seatbelt violation log into the effect log | sandbox-runtime |
| Shims, hooks, proxy, mirror, outbox, review, policies, labels | Same code | |
| User namespace limit, seccomp | Not applicable | |

Differences to accept:

- **Path.** Without private mount namespaces a mount is visible to everyone,
  so the branch cannot sit at the workspace's own path; the agent sees it at
  the mount path. Tools that record absolute paths (transcripts, caches)
  notice.
- **Whiteouts.** overlayfs marks deletions with a character device, which a
  regular user cannot create on macOS. The NFS overlay needs its own marker,
  and review reads both.
- **No pid namespace.** The agent sees the user's processes; the profile should
  deny signalling and inspecting processes outside its own tree.

### To check on a real Mac first

`cmd/airbag-macprobe` checks these on your Mac. It needs no root. It writes
inside a temporary directory and removes it, plus one dot file in `~` that it
removes at once, and mounts the NFS export under that directory for the run;
if the export will not unmount, it says so, leaves the directory and exits 1
(130 when interrupted). Its NFS server, on a localhost port, grants one mount,
on a random path, to the probe's own `mount_nfs`, refuses every other mount
request, and takes no new connection once that mount is up. The path is
visible in the process list while `mount_nfs` runs: a local process that reads
it and mounts first gets the export and, through the resolve-then-use race in
go-billy's BoundOS, possibly files outside it, for the few moments until the
probe's own mount fails and the server drops that process's connection. When
the probe's mount does not come up, for that or any other reason, N1 fails and
the server closes, with every connection it took. N3 runs `claude --version`
and `codex --version` if they are installed, which may write their own files:

```console
$ go run ./cmd/airbag-macprobe            # one line per check
$ go run ./cmd/airbag-macprobe -json      # the same, to paste into an issue
```

Or build it elsewhere: `GOOS=darwin GOARCH=arm64 go build ./cmd/airbag-macprobe`.
`-no-net` skips what reaches the internet (S1's control on 1.1.1.1, and T1),
`-files N` sizes the speed checks (5000 by default), `-v` prints command output
under passing checks. The JSON report replaces the temporary directory, `~` and
your user name; read it before pasting.

| Check | What it answers |
|---|---|
| S1 | A deny-first Seatbelt profile around a shell: writes only in the workspace (refused in another directory and in `~`), a credentials directory unreadable, outbound traffic only to the proxy's localhost port (shown on a second local port that is reachable outside the profile, and on the internet when it is reachable from the Mac) |
| S2 | The denials from S1 can be read from the unified log without admin rights, so review can list blocked operations: a log entry that is a `deny` and names S1's file (not one where the path is `<private>`) |
| N1 | `mount_nfs` mounts an NFSv3 export served from a localhost port by a regular user; read, write, rename, mkdir and delete reach the export |
| N2 | How much slower creating and walking a `node_modules`-sized tree is through the mount |
| N3 | git works in a repository at the mount path (without your git config or `GIT_*` variables); the agents' versions there, if installed |
| C1 | An APFS clone (`clonefile`, which fails where cloning is not supported, unlike `cp -c`, which falls back to a copy) of the same tree: if it is independent, a first prototype can branch the workspace by cloning it, with no NFS server, and review and apply by comparing the clone with the original. The speed is reported for `cp -c -R`, which the prototype runs and which clones file by file, and for one `clonefile` of the tree, each against `cp -R` |
| T1 | A Go program inside the profile verifies TLS through the proxy without `com.apple.trustd.agent` (and with it, to compare), with `SSL_CERT_FILE` and `SSL_CERT_DIR` unset: with either set, a program whose `go.mod` says `go 1.27` or later checks the files and skips the platform verifier, which a program with an earlier go line always uses; skipped when the same request outside the profile does not get through |

### Results from CI

CI runs the probe on GitHub's hosted runners for macOS 15 and 26 on Apple
silicon and macOS 26 on Intel, and keeps its JSON report as an artifact. The
first runs (October 2026) gave the same answer on all three:

| Check | Result |
|---|---|
| S1 | pass |
| S2 | pass, as the runner's user, who is an admin; not yet shown for a user who is not |
| N1 | pass, as that admin user |
| N2 | fail: the walk saw 1375 of 5000 files, then a stale NFS file handle |
| N3 | fail: `git commit` could not close a loose object file (permission denied) |
| C1 | pass: `cp -c -R` 1.6 to 2.9 times and one `clonefile` 26 to 38 times faster than `cp -R`, varying between runs |
| T1 | fail without `trustd`, pass with it, as sandbox-runtime reports |

So the clone stays the branch: an NFS overlay needs a server that keeps file
handles valid for a tree that size and that git can write to, which the probe's
does not. The prototype's profile leaves `trustd` out, so a Go program in the
sandbox that uses the platform verifier (any with a go line before 1.27, or
with `SSL_CERT_FILE` and `SSL_CERT_DIR` unset) cannot verify TLS; whether to
allow it, as sandbox-runtime does, is open.

### Order

1. Seatbelt profile and proxy, with an APFS clone as the workspace branch.
   This is the prototype below.
2. NFS overlay branch of the workspace instead of the clone, if the probe
   (`cmd/airbag-macprobe`) shows it works without root
   and fast enough: the agent then works at a path of its own without a copy.
3. Secret tracking through the same server.

## The prototype

`airbag` builds for macOS and runs the agent natively, without a VM. It is a
prototype: CI runs its unit tests and `test/e2e.sh` on hosted macOS 15, 26
and 26 Intel runners (the agent's workspace edits, the read-only `~`, unreadable
secret files, the denied `memory/`, the outbox, review, apply and rollback),
but it has not yet been used on real work. `test/claude-mac-e2e.sh` runs the
real Claude Code 2.1.291 TUI against a mock API: a `!` command, the Bash
tool, workspace review and the push outbox. It uses a fake HOME and API key,
so it does not validate a real account login.

```console
$ go build ./cmd/airbag        # on the Mac, or GOOS=darwin GOARCH=arm64 elsewhere
$ ./airbag doctor              # sandbox-exec, and an APFS clone to the session dir
$ cd ~/src/project
$ ./airbag run -- claude --dangerously-skip-permissions
$ ./airbag review              # then apply, apply --branch NAME, or discard
```

Claude Code's macOS login is stored in Keychain, which this profile hides.
Provide `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` in the host environment
before starting airbag. `claude setup-token` outside airbag can create an OAuth
token. A "Login expired" message inside the sandbox can mean the login is
inaccessible, even when `claude auth status` outside it reports logged in.

airbag sets both `TMPDIR` and `CLAUDE_CODE_TMPDIR` to the session's temp
directory. Claude Code uses `/tmp` for its own files on macOS unless the
[second variable](https://code.claude.com/docs/en/env-vars) is set; `TMPDIR`
alone does not redirect those files. An inherited `CLAUDE_CODE_TMPDIR` is
replaced, so a `!` command and the Bash tool do not need writes to host temp.

| | Linux | macOS prototype |
|---|---|---|
| Workspace branch | overlayfs, at the workspace's own path | an APFS clone (`cp -c`) in the session directory; the agent works at that path |
| `$HOME` | a branch, reviewed: agent state goes through the branch, only the login and this workspace's transcripts pass through | read-only, except the agent's state (`~/.claude`, `~/.codex`), within which settings, hooks, rules, output styles, workflows, agent memory and instructions stay read-only; caches (`TMPDIR`, Go, npm, pip, uv, cargo) point into the session |
| Agent state in `$HOME` | through the branch (one `agent state` line in review), dropped on discard | writable in place, persists, not reviewed (no branch of `$HOME`) |
| `~/.claude.json` | through the branch, reviewed by key name: counters listed as benign, MCP servers, permissions and trust flagged `persist`; nothing reaches the real file before apply | writable in place, persists in full, not reviewed |
| A project's `memory/` | in the branch, flagged `agent instructions`, dropped on discard | every project's `memory/` denied by the profile: an edit fails rather than being reviewed |
| Network | network namespace, only the proxy | Seatbelt allows outbound traffic only to the proxy's localhost port and airbag's control socket |
| Secret files | served through FUSE, a read taints the session | not readable at all, in the clone or the real workspace (no FUSE, so a read could not be tracked) |
| Credentials | hidden by bind mounts | denied by the profile |
| Shims, outbox, mirror, policies, review, apply, rollback, `--branch`, `--session` | yes | the same code |
| Agent hooks (steps per tool call) | managed settings in a private `/etc` | not installed: managed settings need root on macOS |
| Terminal | a pseudo-terminal of its own, TIOCSTI filtered | the agent shares your terminal |
| An airbag killed under the agent | the agent's pid namespace goes with it | the agent keeps running, and holds the session's agent lock, which airbag passes to it: a rollback and `--session` wait until the agent exits, and until a process it left running that keeps the descriptor does (`lsof` on the session's `agent.lock` finds it; one that closes or unlocks it is not waited for) |

Because the prototype has no branch of `$HOME`, the narrowing that keeps agent
state out of the real files on Linux cannot be expressed in full by the Seatbelt
profile. What it does express: writing any project's `memory/` is denied, as are
the instruction and settings files listed above, so Claude Code's auto-memory
cannot persist unreviewed (the cost is that a memory edit fails instead of being
dropped on discard). Because a deny on a path does not cover renaming one of its
ancestors, `~/.claude`, `~/.codex`, `~/.claude/projects` and each project
directory cannot be created, removed or renamed either; airbag makes this
workspace's project directory before the run. Seatbelt checks the path a write
resolves to, so a `memory/` that is a link, or lies under a linked project
directory or a linked `~/.claude/projects`, is denied where it really is too,
with the directories above that place. Seatbelt rules match paths, not files: a
file in a passed-through path that has another hard-linked name is denied (the
whole path, when it cannot be checked in full), and when a memory file or other
protected file has another name, or the protected files cannot all be checked,
both `~/.claude` and `~/.codex` stay read-only for the session, since a write
through that name would not be a write to the denied path. A protected path that
is a link (a `hooks/` kept in a dotfiles repository) is checked where it leads.
This is checked when the session starts, and counts every other name, even one
outside any place the agent may write: a dotfiles setup that hard-links
`~/.claude/CLAUDE.md` makes the state read-only, and airbag says which file to
turn into a copy or a symlink. What it cannot:
`~/.claude.json` stays writable, so a change to it — including MCP servers,
permissions and per-project trust — persists in full without review, and the
rest of `~/.claude` and `~/.codex` persists as before. Protection there is by
path, and Seatbelt matches paths, not files: a protected file with another name in
a place the agent may write (`~/.claude.json`, a temporary directory) can be
written through that name. airbag does not add a rule for each such layout; the
fix is to give the agent its state in the session instead (see the roadmap), or a
branch of `$HOME` on macOS (the NFS overlay, step 2 above), after which the same
code path applies. Independently of the platform, Codex keys its
transcripts by date (`~/.codex/sessions/<year>/<month>/…`), not by project, so a
discard keeps every project's Codex transcripts, not only this workspace's.

What to report from a first run: whether Claude Code and Codex start and finish a
task, which Seatbelt denials they hit (`log stream --predicate 'eventMessage
CONTAINS "airbag-s-"'` shows them with the session's tag), and how long the clone
takes on a large repository.

## The tested way: a Linux VM

Until the prototype has been used on real work, the way to use airbag on a Mac
that the tests cover in full is a Linux VM.

**OrbStack.** Create an Ubuntu machine and install airbag inside it. Mac files
are under `/mnt/mac`; a server on the Mac is reachable as `host.orb.internal`.

**Lima.** `limactl start --vm-type=vz template://ubuntu-lts`. Lima 1.0+ mounts
your Mac home read-only by default; `airbag apply` writes to the workspace, so
mount the projects directory writable:

```yaml
mounts:
  - location: "~/src"
    writable: true
```

Log in to the agent inside the VM, and give the VM your git credentials:
the outbox pushes from there.

The Mac's home is visible in the VM outside the VM's `$HOME`
(`/Users/<you>` in Lima, `/mnt/mac/Users/<you>` in OrbStack). airbag hides the
credentials in every Mac home it finds there, as in the VM's own home (`~/.ssh`,
`~/.aws`, ... plus the Mac's keychains, sops keys and browser profiles), but the
rest of the Mac's files stay readable: share only the projects directory with the
VM.
