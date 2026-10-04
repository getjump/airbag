# airbag on macOS

airbag is built on Linux namespaces, overlayfs and FUSE; macOS has none of
them. This page records how the agents and agent sandboxes that run natively
on macOS do it (as of October 2026), the native design that follows for
airbag, and the Linux VM setup that works until then.

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

- [ ] `mount_nfs` from a localhost server works without root on current macOS
  (AgentFS's documentation does not mention sudo).
- [ ] NFS speed on a large `node_modules` tree.
- [ ] Claude Code and Codex run normally with the workspace at the mount path.
- [ ] The violation log can be read without admin rights.
- [ ] Go tools (`gh`, `terraform`) work through the proxy without opening
  `trustd`.

### Order

1. Seatbelt profile and proxy, with an APFS clone as the workspace branch.
   This is the prototype below.
2. NFS overlay branch of the workspace instead of the clone, if the probe
   (`cmd/airbag-macprobe`, see the macos-probe PR) shows it works without root
   and fast enough: the agent then works at a path of its own without a copy.
3. Secret tracking through the same server.

## The prototype

`airbag` builds for macOS and runs the agent natively, without a VM. It is a
prototype: built and unit-tested on Linux, not yet run on a Mac.

```console
$ go build ./cmd/airbag        # on the Mac, or GOOS=darwin GOARCH=arm64 elsewhere
$ ./airbag doctor              # sandbox-exec, and an APFS clone to the session dir
$ cd ~/src/project
$ ./airbag run -- claude --dangerously-skip-permissions
$ ./airbag review              # then apply, apply --branch NAME, or discard
```

| | Linux | macOS prototype |
|---|---|---|
| Workspace branch | overlayfs, at the workspace's own path | an APFS clone (`cp -c`) in the session directory; the agent works at that path |
| `$HOME` | a branch, reviewed | read-only, except the agent's state (`~/.claude`, `~/.codex`, without their settings, hooks and instructions); caches (`TMPDIR`, Go, npm, pip, uv, cargo) point into the session |
| Network | network namespace, only the proxy | Seatbelt allows outbound traffic only to the proxy's localhost port and airbag's control socket |
| Secret files | served through FUSE, a read taints the session | not readable at all, in the clone or the real workspace (no FUSE, so a read could not be tracked) |
| Credentials | hidden by bind mounts | denied by the profile |
| Shims, outbox, mirror, policies, review, apply, rollback, `--branch`, `--session` | yes | the same code |
| Agent hooks (steps per tool call) | managed settings in a private `/etc` | not installed: managed settings need root on macOS |
| Terminal | a pseudo-terminal of its own, TIOCSTI filtered | the agent shares your terminal |

What to report from a first run: whether Claude Code and Codex start and finish a
task, which Seatbelt denials they hit (`log stream --predicate 'eventMessage
CONTAINS "airbag-s-"'` shows them with the session's tag), and how long the clone
takes on a large repository.

## Until then: a Linux VM

If you need airbag on a Mac before the native port, run it in a Linux VM.

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
