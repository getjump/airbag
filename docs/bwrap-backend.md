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
   user namespaces of its own (see the last section).
2. Revisit when Ubuntu LTS ships bubblewrap 0.10 or later. With `--overlay`
   in bubblewrap, a hybrid (bubblewrap for namespaces and binds, an airbag
   helper inside for the rest) becomes worth measuring.

## What airbag needs, and what bubblewrap 0.9 does

| airbag step | bubblewrap 0.9 | Probe |
|---|---|---|
| User, mount, pid, net, ipc namespaces; uid map | Yes: `--unshare-*`, `--uid` | |
| Host read-only | Yes: `--ro-bind / /` | `$HOME`, `/tmp`, `/var/tmp` read-only inside. bubblewrap remounts submounts read-only too; this machine has no writable submounts to show it |
| Loopback-only network | Yes: `--unshare-net` | `/proc/net/dev` inside lists only `lo` |
| Copy-on-write branch of workspace and `$HOME` | **No.** `--overlay` came after 0.9, and is not available when bubblewrap is installed setuid | Overlay works when a nested user namespace inside the sandbox mounts it (upper gets the change, lower untouched) |
| Pass-through and hidden paths in `$HOME` | Yes: `--bind`, `--tmpfs`, `--ro-bind /dev/null` | They go on top of the branch, so they wait on the overlay |
| Agent settings in `/etc` (`managed-settings.d`, `requirements.toml`) | **No**, when the directory does not exist on the host | `--ro-bind-data` and `--tmpfs` need the mount point: `Can't mkdir parents … Read-only file system`. airbag overlays `/etc` |
| Private `/run`, `/tmp`, `/var/tmp`, `/dev/shm` | Yes: `--tmpfs`, `--dev` | |
| Secret files through FUSE | **No** | The sandboxed process has no capabilities (`CapEff: 0`), so it cannot mount FUSE. The alternative, `fusermount3` on the host, is a setuid dependency |
| Proxy at `127.0.0.1:3128` inside | **No** | Needs a process inside that bridges TCP to the proxy's unix socket; Claude Code's own sandbox runs such a helper |
| Agent cannot create user namespaces | Yes: `--disable-userns` | `unshare -Ur` inside fails with ENOSPC. airbag does not do this yet |
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
That closes a large kernel surface to whatever runs inside. The cost: the
agents' own sandboxes, Codex's `--sandbox workspace-write` and Claude Code's
sandbox mode, run on bubblewrap and need user namespaces, so they would no
longer start inside airbag. airbag already advises turning them off in favor of
its own branch, so the limit can be the default with a flag to lift it.
