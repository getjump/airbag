# airbag on macOS

airbag is built on Linux namespaces, overlayfs and FUSE. macOS has none of
them, so today airbag runs on a Mac inside a Linux VM. This page covers that
setup, what to check in it, and a design sketch for running natively later.

## Today: a Linux VM

Any recent Linux VM works. Two that are quick to set up:

**OrbStack.** Create an Ubuntu machine, install Go and airbag inside it. Mac
files are visible in the machine under `/mnt/mac`, and the machine user has
your Mac user name. A server running on the Mac is reachable from the machine
as `host.orb.internal`.

**Lima.** `limactl start --vm-type=vz template://ubuntu-lts`. Lima 1.0+ mounts
your Mac home into the VM with virtiofs, read-only by default. airbag only
reads the workspace while the agent works, but `airbag apply` writes to it, so
mount the projects directory writable in the instance config:

```yaml
mounts:
  - location: "~/src"
    writable: true
```

Then, inside the VM:

```console
$ go install github.com/getjump/airbag/cmd/airbag@latest
$ airbag doctor          # Ubuntu 24.04 restricts user namespaces; doctor prints the fix
$ cd /path/to/project && airbag run -- claude --dangerously-skip-permissions
```

The agent, its login and its state live in the VM: log in to Claude Code or
Codex inside the VM. `git push` from the outbox runs in the VM too, so the VM
needs your git credentials.

### Mind the Mac files the VM can see

airbag hides `~/.ssh`, `~/.aws` and other credentials relative to `$HOME`, which
is the VM's home. The Mac's own home is visible in the VM under another path
(`/Users/<you>` in Lima, `/mnt/mac/Users/<you>` in OrbStack), and airbag does
not hide it yet: the agent can read whatever the VM can read there, including
the Mac's `~/.ssh`. Until airbag hides those mounts, share only the projects
directory with the VM (Lima: list it under `mounts` instead of `~`; OrbStack:
see its file sharing settings).

### What to check on the first run

These work on Linux; under a VM they depend on the shared file system, and
have not been tried yet:

- [ ] `airbag doctor` passes, `test/e2e.sh` passes with the workspace on the
  shared mount (overlayfs over virtiofs as the lower layer needs Linux 5.7+).
- [ ] `airbag apply` writes the changes back through the shared mount.
- [ ] The conflict check notices a file you edit on the Mac while the agent
  works (it compares change times, which a shared file system may report
  differently).
- [ ] `test/secret-e2e.sh` passes (FUSE inside the VM).
- [ ] A service on the Mac is reachable through `--allow` with the host name
  above.

## Later: native macOS

How each Linux mechanism could map, and how hard it looks:

| airbag on Linux | macOS candidate | Notes |
|---|---|---|
| Network namespace, only the proxy | Seatbelt profile (`sandbox-exec`): deny outbound except the proxy port and allowed localhost ports | The agents' own macOS sandboxes use Seatbelt. Seatbelt cannot filter remote hosts by name, so everything goes through airbag's proxy, as on Linux |
| Read-only host, hidden credentials | Seatbelt: deny writes outside allowed paths, deny reads of `~/.ssh`, `~/.aws` and the rest | Direct fit |
| Copy-on-write branch of the workspace | APFS `clonefile` copy into the session, agent works in the copy, `apply` copies changes back | Cheap clones, but the agent sees a different path than the real one; tools that record absolute paths notice. A user-space overlay (FSKit, macFUSE) would keep the path, at much higher cost |
| Branch of `$HOME` | `$HOME` read-only except pass-through agent state | Simpler than a branch: writes to dotfiles are refused instead of reviewed |
| `.env` reads tracked through FUSE | FUSE-T or macFUSE, or FSKit on recent macOS; otherwise deny reads by anything but the agent | Each option has a cost: a third-party file system, or a newer macOS |
| Shell and git shims, agent hooks | Same | PATH and hooks work the same way |

Suggested order: network and hidden credentials first (Seatbelt alone gives
most of the safety), then the workspace branch through clones, then secret
tracking.
