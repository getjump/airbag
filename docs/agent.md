# What the agent gets

What an agent started with `airbag run` gets, and what it does not. The short
version is in the [README](../README.md#what-you-get).

## Files

- **A branch of the world.** The workspace and `$HOME` are overlayfs branches; the
  rest of the host is read-only. Nothing the agent writes to the workspace reaches
  your files before `airbag apply`, and almost nothing it writes to `$HOME` does
  either — the exceptions are the narrow agent state below, which has to survive a
  discard.

## Network

- **One way out.** The sandbox has no network interface besides loopback and no
  DNS. Traffic leaves only through airbag's proxy, which allows model APIs
  (`--allow HOST` adds more) and logs every host. Package registries are reached
  only through the mirror. Allowed hosts are reached on ports 80 and 443;
  another port needs an entry that names it (`--allow git.corp:8443`). An
  allowed name that resolves to this machine, loopback, link-local (cloud
  metadata) or multicast is refused: the address is checked as the proxy
  connects, so a DNS answer cannot change between check and use. The proxy
  runs on the host, so what the agent holds open there is bounded. A
  connection through it is closed when no byte has moved for 15 minutes, when
  it has waited 2 minutes for its next request, or, once one side has finished
  sending, when the other has been quiet for 30 seconds. A session holds at
  most 512 tunnels and forwarded requests at once (the mirror's are not
  counted); one more gets `503`. It holds at most 1024 connections to the
  proxy, counting those that wait for a request; one more is closed.
- **Local services, by name.** `--allow tcp://127.0.0.1:5432` (or `allow:` in
  `airbag.yaml`) gives the agent `127.0.0.1:5432` in the sandbox, relayed by airbag
  to that address: a dev database, a cache, a service from `docker compose`. Each
  connection is checked by policy (as a `net.connect` effect) and logged as
  `net.tcp`. After a secret read, forwards to other machines are refused and cut;
  forwards to this machine stay. A forwarded connection is closed after an hour
  without a byte (database pools keep theirs idle long), or as at the proxy
  once one side has finished; each forward relays at most 256 at once. The
  Docker socket itself stays hidden.
- **A package mirror.** Go, npm, pip, uv and yarn go through
  `http://airbag.mirror`, a read-only caching mirror of proxy.golang.org, npm and
  PyPI. Review lists every package and version the agent pulled; artifacts are
  cached across sessions.

## Outbox

- **An outbox.** `git push` returns `queued` and runs on the host after you approve
  it. Pushing around the shim fails at the proxy. If the session put git config or
  hooks into the repository, its pushes wait for `airbag apply --trust-git` and
  run with hooks off. A push cut off by a crash is reported as of unknown outcome
  and never run again. Other commands wait there when `defer:` names them
  ([deferred commands](policies.md#deferred-commands)).

## Credentials and secrets

- **No credentials.** `~/.ssh`, `~/.aws`, `gh`, `docker`, `kube` and similar are
  hidden, and so are credential-like environment variables (`*TOKEN*`,
  `*SECRET*`, `*API_KEY*`, ...) except the agents' own API keys; `--pass-env NAME`
  keeps one. Decryption keys and decrypted secrets are hidden too: sops and age
  keys, sops-nix's runtime secrets, `pass`, Vault, rclone, keyrings; `hide:` in
  `airbag.yaml` adds paths. Host sockets (docker.sock, D-Bus, ssh-agent, X11,
  Wayland) are out of reach: `/run`, `/tmp` and `/dev/shm` are private. Daemons
  that keep their socket elsewhere are hidden by name: Incus and LXD (root for
  their admin group) and the Nix daemon, whose builds reach the network outside
  the proxy; `--nix-daemon` gives the agent Nix anyway.
- **Tokens it uses but never holds.** A credential you bind to hosts in your own
  `~/.config/airbag/airbag.yaml` reaches the agent as a placeholder; airbag's
  proxy puts the real value in on the way to those hosts and takes it out of
  what comes back ([credentials](policies.md#credentials)).
- **Watched secrets.** The workspace's secret files are served read-only through
  FUSE (`.env` and `.env.*` at any depth, private keys, `.npmrc`, `.pypirc`,
  cloud credentials, `*.tfvars`). The first read by anything but airbag taints
  the session: commands that send data out are refused, only model APIs stay
  reachable, and the mirror serves only what it has cached or what the workspace's
  lock files pin (`package-lock.json`, `yarn.lock`, `go.sum`, `uv.lock`, read from the
  real workspace before the agent starts, so a build from the lock file keeps
  working). The read returns only
  after airbag has recorded the taint and closed connections opened earlier to
  other hosts. Without FUSE the secret files are hidden instead. Known secret
  values are masked in the output of shell commands; the agent's own file tools are
  not filtered, and model APIs stay reachable, so a secret the agent reads can
  reach its model. The label stops it from going anywhere else.

## Terminal and kernel

- **A terminal of its own.** The agent runs in a session of its own on a
  pseudo-terminal that airbag copies to yours, as `sudo` with `use_pty` and
  `docker run -t` do. Input it pushes into its terminal (TIOCSTI) or modes it
  sets stay in that pseudo-terminal, never in the shell you return to; a
  seccomp filter refuses TIOCSTI and TIOCLINUX as well, and the agent runs
  with `no_new_privs`. Ctrl-C, Ctrl-Z with `fg`, and resizing work as usual.
- **Less kernel to attack.** The same seccomp filter is allow-by-default and
  refuses a set of syscalls that widen the kernel's attack surface: io_uring
  (which can open sockets without a `socket()` call), `bpf`,
  `perf_event_open`, `userfaultfd`, the kernel keyring
  (`add_key`/`keyctl`/`request_key`), `kexec`, module loading,
  `open_by_handle_at`, `quotactl`, `acct`, `swapon`, `reboot`, `syslog`,
  `move_pages`, `migrate_pages`, `fanotify_init`, and sockets (`socket` and
  `socketpair`) of families other than Unix, IPv4/IPv6 and netlink, so
  `AF_VSOCK`, `AF_PACKET` and `AF_TIPC` are out. An `AF_NETLINK` socket is
  allowed, but not the `NETLINK_NETFILTER` and `NETLINK_XFRM` protocols,
  which reach nf_tables and the IPsec state. It stays allow-by-default so
  nested user namespaces, `mount`, `pivot_root`, `setns` and the rest that
  Codex's and Chromium's own sandboxes use keep working; `ptrace` stays
  allowed for the agent's own programs (gdb, strace, `go test -race`). It
  covers the native ABI and every compat one and kills an unknown
  architecture, so a refused call cannot slip past by its number on a 32-bit
  or x32 entry. Two gaps remain in the default mode. A 32-bit (i386) program
  can still create a socket of any family or netlink protocol through the
  `socketcall` multiplexer, whose arguments are behind a pointer the filter
  cannot read. And the agent can make its own user and network namespace,
  where it is root, and there still reach `NETLINK_ROUTE` (traffic control,
  qdiscs), generic netlink and the legacy x_tables `setsockopt` interface.
  `--strict` closes both: it refuses i386 socket creation and forbids new
  user namespaces. The second is not covered when airbag runs as root: the
  agent is then root in its own namespace, where a network namespace needs
  no new user namespace.
  Alongside the filter: the agent's `/proc` hides other processes
  (`hidepid`) and `/dev/kmsg` and `/dev/userfaultfd` are hidden; the agent
  cannot ptrace the supervisor or read its `/proc/1/mem` or `/proc/1/environ`
  (its user namespace has no `CAP_SYS_PTRACE` over PID 1, and PID 1 is set
  non-dumpable as a second layer); file descriptors inherited from the caller
  are closed before the agent starts; and core dumps are capped at 1 byte
  (`RLIMIT_CORE=1`). That stops file dumps and a `core_pattern` that pipes to
  a host handler like systemd-coredump, unless something in the sandbox
  lowers the limit (`--strict` silently skips that change). A socket
  `core_pattern` (`@` or `@@`, Linux 6.16+) ignores the limit and is not
  covered; `airbag doctor` reports which kind the host uses.

  What this gives up, in return: `perf`, `bpftrace`/`bcc` and
  `async-profiler`'s perf mode do not work (no `perf_event_open`/`bpf`);
  tools that cache credentials in the kernel keyring (some Kerberos
  `KEYRING:` ccaches) do not; inside the agent's own namespaces, nftables,
  iptables-nft, `conntrack` and rootless Podman networks (netavark) do not
  (`NETLINK_NETFILTER`), nor do `ip xfrm` and strongSwan (`NETLINK_XFRM`);
  numactl's `migratepages` and the `move_pages` calls of libnuma and hwloc do
  not; fanotify tools such as `fatrace` do not; and under `--strict`, 32-bit
  networking and nested mounts through the new mount API do not. The agents
  themselves and the usual build and test tools do not use any of these; a
  `strace -f -c` over a Claude Code and a Codex run touches none of the
  refused calls.
- **A strict mode.** `airbag run --strict` also keeps the agent from creating
  user namespaces, so the kernel features only a user namespace exposes stay
  out of its reach, and in this mode only the filter refuses the new mount
  API (`fsopen`, `fsconfig`, `open_tree`, `move_mount`, `mount_setattr`, …)
  with `ENOSYS`, as Flatpak does, so a nested mount cannot reconfigure the
  VFS, and refuses i386 `socketcall` socket creation. A change to the
  core-dump limit is silently skipped: `setrlimit` or `prlimit64` on
  `RLIMIT_CORE` returns success without running, and the limit stays 1 byte,
  so gpg and `ssh-agent`, which lower it at start, keep working. Reading the
  limit still works, and a `prlimit64` that sets it and also asks for the
  old value is refused. If any of this cannot be set up, the run stops. It
  is off by default because common tools need user namespaces: Codex's own
  `--sandbox` modes and Chromium's sandbox fail under it (run Codex with
  `--dangerously-bypass-approvals-and-sandbox`, Chromium with `--no-sandbox`).

## Sessions and agent state

- **More than one run.** `airbag run --session last -- claude --continue` runs the
  agent again on the branch of a stopped session: it sees its own earlier changes,
  the outbox and the effect log continue, and what the session learned stays (a
  secret read in the first run still narrows egress in the second). Iterate
  "agent, review, tell it what to fix, agent again" without applying in between.
- **Its own state.** Only what must survive a discard passes straight through to the
  real `$HOME`: the login (`~/.claude/.credentials.json`, `~/.codex/auth.json`, so a
  discard does not log you out), the current workspace's Claude Code transcripts
  (`~/.claude/projects/<this project>/`, so `claude --resume` works after a discard) and
  Codex's transcripts and logs (`~/.codex/sessions`, which Codex keys by date, not by
  project, so these are not narrowed to the workspace, and `~/.codex/log`). Mind what that means: a transcript the
  agent wrote, resumed later outside airbag (`claude --continue`, `codex resume`),
  brings that conversation back, so resume a sandboxed session inside airbag
  (`airbag run --session`), and a login the agent changed inside a session is the
  login your next host session uses. A path with a symlink in it (say `~/.claude`
  pointing into a dotfiles repository) is not passed through: it stays in the branch,
  or is read-only where the link leads out of `$HOME`. Nor is one holding a file with
  another hard-linked name, which a write through it would change for real, or more
  than 100 000 files to check for one. A session started by an older
  airbag, resumed now, gets today's narrower list. Resumed from another directory,
  a session passes that directory's transcripts through too, unless an earlier run
  already changed them in the branch: then they stay in the branch, and airbag says so. Everything else an agent keeps in
  `$HOME` — other projects' transcripts, sessions, shell snapshots, file history,
  todos, caches — goes through the branch: review folds it into one `agent state`
  or `cache` line, and neither a discard nor an apply carries it to the real `$HOME`
  (a download cache holds code a host build runs as it is; `apply --only` naming a
  `~/` path takes it anyway). Codex's thread index is in that state, so a sandboxed
  Codex session is resumed with `airbag run --session`, not with `codex resume` on the
  host. The exception is shell code Claude Code sources: a
  change to a shell snapshot the host already has, and any change to a session's env
  files (the host can resume a session by id), is flagged `persist` and shown in full;
  the sandbox session's own new snapshots stay folded. A project's `memory/` (instructions loaded into later
  sessions) stays in the branch too, flagged `agent instructions`, so you see it and
  a discard drops it. `~/.claude.json` goes through the branch too, the whole file:
  nothing in it reaches the real file before apply, Claude Code's own counters
  included. Review shows it by key name, never value: keys the CLI rewrites every
  run (counters, ids, migration markers) as `benign key(s)`, which need no decision;
  an MCP server, a tool permission, a trust decision or the logged-in account flagged
  `persist`; any other key as `unknown key(s)`. A new project's entry, written with the
  CLI's own defaults (`false`, `[]`, `{}`, each where it belongs), is no change; a mode
  that lets other users write the file is flagged. The legacy `~/.claude/.config.json`
  is reviewed the same way, and a new one, which the CLI reads instead of
  `~/.claude.json`, is flagged. If the host
  rewrote or removed the file during the session, apply reports it as a conflict; leave
  it out with `apply -i` or `--only`. Dotfiles kept as links (`~/.bashrc`, `~/.claude`,
  `~/.claude.json` or a file deep in `~/.config/nvim` pointing into `~/dotfiles`, or into
  the workspace when that is your dotfiles repository) are followed, through chains and
  to targets that do not exist yet: a change found at a link's target is classified as
  the path it stands for (apply writes a regular file in place of a link it replaces).
  A link deeper than 5000 entries into a watched directory is not looked for, and
  instruction files recognized by name wherever they are (`AGENTS.md`, `CLAUDE.md`) are
  recognized by their own name only: a write through one that is a link to a file named
  otherwise is shown under the target's name. On the macOS prototype,
  which has no branch of `$HOME`, this narrowing is only partial; see
  [macos.md](macos.md).
