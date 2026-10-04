# bubblewrap as airbag's isolation backend

An evaluation, 2026-10-04: bubblewrap 0.9.0 (the version Ubuntu 24.04 ships),
kernel 6.18, run as a regular user. The probes are reproducible with the
commands quoted below.

## Recommendation

Not now. bubblewrap would take over the least risky part of airbag: creating
namespaces, mapping uids and binding paths. The parts that are hardest to get
right would stay airbag's either way: the copy-on-write branch, secret files
over FUSE, the bridge to the proxy and the agent settings in `/etc`. On 0.9,
bubblewrap cannot create overlay mounts at all.

Two things to do instead:

1. Take bubblewrap's `--disable-userns` idea now: keep the agent from creating
   user namespaces of its own (see the last section). Done as
   `airbag run --strict`, off by default.
2. Revisit when Ubuntu LTS ships bubblewrap 0.11 or later. With `--overlay`
   in bubblewrap, a hybrid (bubblewrap for namespaces and binds, an airbag
   helper inside for the rest) becomes worth measuring.

Upstream since the probe ([NEWS](https://github.com/containers/bubblewrap/blob/main/NEWS.md)):
0.11.0 (2024-10-30) added `--overlay`, `--tmp-overlay` and `--ro-overlay`, not
available when installed setuid; 0.12.0 (2026-08-26) removed setuid builds and
fixed GHSA-pxhw-h44j-8pfx, where files created during setup could follow parent
symlinks out of the sandbox; 0.13.0 came out on 2026-09-22. What bubblewrap
would still bring is its hardening record: the controlling terminal
(CVE-2017-5226, which airbag now handles with a pseudo-terminal of its own and a
TIOCSTI filter), safe path resolution during setup, `--die-with-parent`.

## What airbag needs, and what bubblewrap 0.9 does

| airbag step | bubblewrap 0.9 | Probe |
|---|---|---|
| User, mount, pid, net, ipc namespaces; uid map | Yes: `--unshare-*`, `--uid` | |
| Host read-only | Yes: `--ro-bind / /` | `$HOME`, `/tmp`, `/var/tmp` read-only inside. bubblewrap remounts submounts read-only too; this machine has no writable submounts to show it |
| Loopback-only network | Yes: `--unshare-net` | `/proc/net/dev` inside lists only `lo` |
| Copy-on-write branch of workspace and `$HOME` | **No.** `--overlay` came in 0.11.0, and is not available when bubblewrap is installed setuid | Overlay works when a nested user namespace inside the sandbox mounts it (upper gets the change, lower untouched) |
| Pass-through and hidden paths in `$HOME` | Yes: `--bind`, `--tmpfs`, `--ro-bind /dev/null` | They go on top of the branch, so they wait on the overlay |
| Agent settings in `/etc` (`managed-settings.d`, `requirements.toml`) | **No**, when the directory does not exist on the host | `--ro-bind-data` and `--tmpfs` need the mount point: `Can't mkdir parents … Read-only file system`. airbag overlays `/etc` |
| Private `/run`, `/tmp`, `/var/tmp`, `/dev/shm` | Yes: `--tmpfs`, `--dev` | |
| Secret files through FUSE | **No** | The sandboxed process has no capabilities (`CapEff: 0`), so it cannot mount FUSE. The alternative, `fusermount3` on the host, is a setuid dependency |
| Proxy at `127.0.0.1:3128` inside | **No** | Needs a process inside that bridges TCP to the proxy's unix socket; Claude Code's own sandbox runs such a helper |
| Agent cannot create user namespaces | Yes: `--disable-userns` | `unshare -Ur` inside fails with ENOSPC. airbag now does the same (below) |
| Signals, terminal, reaping | Yes: `--die-with-parent`, `--new-session`, a PID 1 reaper | |

## What a bubblewrap backend would look like

bubblewrap creates the namespaces, the read-only root, `/proc`, `/dev` and the
tmpfs mounts, and starts an airbag helper as the sandboxed command. The helper
needs a nested user namespace of its own to mount the overlays, FUSE and the
`/etc` settings, runs the proxy bridge, then limits user namespaces and starts
the agent. That is the structure airbag has today, with bubblewrap in place of
the first stage. The overlay, the read-only remount of the overlays, FUSE and
mount locking stay in airbag's code.

## Disabling nested user namespaces

bubblewrap's `--disable-userns` works by setting `max_user_namespaces` to 1 in
the sandbox's user namespace before creating the one the program runs in. The
same works in airbag's first stage, which is root in its own user namespace:

```console
$ unshare -Ur sh -c 'echo 1 > /proc/sys/user/max_user_namespaces
    unshare -Ur sh -c "unshare -Ur true || echo agent-cannot-nest"'
agent-cannot-nest
```

The agent's own namespace is still created; the agent cannot create another.
That closes a large kernel surface to whatever runs inside. airbag does this
under `airbag run --strict`.

It is not the default, because of what it breaks, checked inside airbag:

- Codex 0.160's own sandbox: `codex exec -s workspace-write` fails with
  `bwrap: Creating new namespace failed: nesting depth or
  /proc/sys/user/max_user_namespaces exceeded`. airbag warns when Codex starts
  under `--strict` without `--dangerously-bypass-approvals-and-sandbox`.
- Headless Chromium (Playwright's build): `No usable sandbox!`. It runs with
  Chromium's `--no-sandbox`, as in Docker.

Claude Code with `sandbox.enabled` in project settings still ran its Bash tool
under the limit; whether its sandbox engaged there is not established.
Rootless podman and nix's build sandbox use user namespaces too; not checked.

airbag's own boundaries do not depend on the limit: an agent with a user
namespace of its own still cannot unmount the locked mounts, reach the network
other than through the proxy, or read secret files around FUSE.
