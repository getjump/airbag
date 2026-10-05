# airbag

**Approve outcomes, not commands.** Start a long agent task without permission
prompts and do something else. The agent works in a copy-on-write branch of your
workspace and `$HOME`, `git push` and the commands you name wait in an outbox, and
every host it reaches is logged. When you come back, one review shows what changed and what is waiting:
apply it, take it onto a git branch, or throw it away.

```console
$ airbag run -- claude --dangerously-skip-permissions
$ airbag run -- codex --dangerously-bypass-approvals-and-sandbox   # or Codex
$ airbag review
$ airbag apply        # or: apply -i, apply --branch NAME, or: airbag discard
$ airbag rollback     # undo the last apply
```

![demo: the agent deletes src, reads .env, tries to send it out, plants a line in ~/.bashrc and pushes; airbag review shows all of it; discard, and nothing happened](demo/demo.gif)

The demo runs the real Claude Code; the "model" is `test/mockapi` playing a fixed
script, so it is repeatable without an account (`demo/demo.sh`). `agent ▶` lines are
the calls the model makes, `agent ◀` what the agent sends back. More scenes, one GIF
each, in `demo/`: `sandbox`, `codex`, `ask`, `apply`, `mirror` (`demo/scenes.sh NAME`).

## How it compares

Isolation is not the difference. Claude Code's and Codex's built-in sandboxes run
on bubblewrap on Linux and Seatbelt on macOS, and airbag uses the same kernel
features. What differs is when you decide, and what you get to see.

Say you ask an agent to clean up a repository, and it deletes `src`, reads
`.env`, tries to post it to a paste site, appends a line to `~/.bashrc` and
pushes.

- **Built-in sandbox:** the agent stops for approval as it goes: a write
  outside the workspace, a new domain. You answer prompts mid-run and never see
  the whole result at once, and writes inside the workspace land in place.
- **airbag:** the agent runs without stopping in a branch of your machine.
  Afterwards one review shows all of it: `src` deleted, `.env` read, the upload
  blocked, the `~/.bashrc` line flagged as persistence, the push waiting in the
  outbox. `airbag discard`: the files and `~` are as they were, and the push never
  left. (A request to an allowed host would have happened when it was made; see
  below.)

Tools that also let you decide after the run, at least for files:

| | Files | Network | Pushes, publishes, API calls | Secrets |
|---|---|---|---|---|
| [nono](https://github.com/nolabs-ai/nono) `--rollback` | writes land in place; snapshot before, diff after, restore what you pick | blocked by default, L7 proxy | asked live by its supervisor | stand-in credential, real one injected by the proxy |
| [try](https://github.com/binpash/try) | overlayfs branch of one command, commit or not | unrestricted | run as they happen | not handled |
| [AgentFS](https://github.com/tursodatabase/agentfs) | copy-on-write branch of the working directory (SQLite delta), `agentfs diff`; no apply command | not controlled | run as they happen | not handled |
| [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) in clone mode, or [Code Airlock](https://github.com/Trivo25/code-airlock) on top of it | microVM with a private clone, host repo read-only; review and merge with `git fetch`, `git diff` | allowlist through a proxy | not held | proxy injects credentials, values stay outside the VM |
| Claude Code sandbox and checkpoints | writes in the workspace, `/rewind` restores the agent's own file edits, not Bash's | allowlist through a proxy, asks for new domains | auto mode's classifier blocks some | denied or masked behind a proxy |
| airbag | copy-on-write branch of the workspace and `$HOME`; persistence flagged; apply all, part or none, or onto a git branch; `rollback` | allowlist, every host logged, mirror, cut on a secret read | `git push` and the commands `defer:` names (`gh pr create`) queued in the outbox, run after review; other publishing fails at the read-only mirror; calls to allowed hosts happen when made, a rule can `ask` | hidden; a read labels the session and narrows egress; tokens you bind reach the agent as placeholders, the proxy puts the value in |

What airbag adds is around the branch rather than the branch itself: the outbox
that holds `git push` and the commands you name until review, the `$HOME` branch with persistence called out,
a label that follows a secret read through the rest of the session, and one review
that works the same for any agent, on your own toolchain without a VM. The result
goes onto your files or onto a git branch, and an apply can be rolled back.
Whether that beats a VM clone or nono for a given team is a matter of measuring,
not of this table. Tools that govern effects at runtime in depth, such as
[agentsh](https://github.com/canyonroad/agentsh) (file, process and network policy
with approvals, an LLM proxy with DLP), go further than airbag's policies do. (As of
October 2026, from each project's documentation.)

### What waits for you, and what does not

| | Until you decide | Examples |
|---|---|---|
| Stays local until `airbag apply` | the workspace and `$HOME` | edits, deletions, new files, a line in `~/.bashrc` |
| Waits in the outbox, runs after review | what airbag intercepts | `git push`, and the calls `defer:` names, such as `gh pr create` or `npm publish` |
| Decided when it happens, by the allowlist and policy | every other network request | model API calls, a request to a host you allowed, packages through the mirror; `ask` holds a call until you approve it |

A call to an outside service cannot be held or undone after the fact, so for those
the allowlist and policy decide beforehand. Review shows that they happened.

airbag sets up its namespaces itself. Could it run on bubblewrap underneath?
Not yet: bubblewrap 0.9, which Ubuntu 24.04 ships, cannot make the overlay the
branch needs, and FUSE, the proxy bridge and the agent settings would stay
airbag's anyway. See [docs/bwrap-backend.md](docs/bwrap-backend.md).

## What the agent gets

- **A branch of the world.** The workspace and `$HOME` are overlayfs branches; the
  rest of the host is read-only. Nothing the agent writes to the workspace reaches
  your files before `airbag apply`, and almost nothing it writes to `$HOME` does
  either — the exceptions are the narrow agent state below, which has to survive a
  discard.
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
- **An outbox.** `git push` returns `queued` and runs on the host after you approve
  it. Pushing around the shim fails at the proxy. If the session put git config or
  hooks into the repository, its pushes wait for `airbag apply --trust-git` and
  run with hooks off. A push cut off by a crash is reported as of unknown outcome
  and never run again. Other commands wait there when `defer:` names them
  ([below](#deferred-commands)).
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
  what comes back ([below](#credentials)).
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
  [docs/macos.md](docs/macos.md).

## What the review shows

```
Workspace  /home/me/api
  Files    +3 ~2 -1    (git internals: 14 files)
  + .git/hooks/pre-commit  persist
  + leak.txt  secret in diff
Home       1 changes outside the workspace
  ~ ~/.bashrc  persist
Network    31 allowed: api.anthropic.com ×30, proxy.golang.org ×1
           1 denied: paste.example.net:443 ×1
Outbox     1
  i-1  git push origin feature/retry               pending
```

`airbag review --attention` prints only what needs a decision: secret reads, flagged
changes, every change in `$HOME` that apply would carry over other than an agent
config change of benign keys only (with the file's mode unchanged), many
deletions, waiting pushes, blocked calls, refusals past the log's rate. Caches and
agent state are not carried over, so they need no decision; a repository's git
directory in `$HOME` is one line with its count of files. In `$HOME` a change is matched by where the write really landed,
so one made through a link (`~/.bashrc` pointing into `~/dotfiles`) shows as a change
to the link's target, which needs a decision even when review cannot tell what the
link stands for. `airbag review --json` prints
the whole review as data for editors and CI, with a versioned schema
(`airbag.review/v1`; fields are only added within a version).

It flags persistence (git hooks, shell rc files, CI config, agent settings), new
executables, changes outside the workspace and values from your `.env` files that
ended up in the diff. `apply` refuses to overwrite files you changed on the host
while the agent worked. `apply -i` goes through the changes one by one (git
internals and caches come as one piece each) and keeps the rejected ones in the
session; `apply --only PATH` takes just part of the branch.

An apply is all or nothing: before a real file changes, what was there moves into
the session, so a step that fails puts back the ones before it. `airbag rollback`
undoes the last apply the same way, and the agent's changes go back into the session
to apply again or discard; a file you edited after the apply is left as it is, and
its version from before the apply stays in the session: `airbag discard` refuses
to delete it until a later rollback restores it, or you pass `--force`. A push that
already ran is not undone.

`apply --branch NAME` leaves your working tree alone and puts the result on a new
branch of the repository instead: the agent's commits, fetched with their history,
then one commit with whatever it left uncommitted (files your `.gitignore` excludes
stay out). Your index, uncommitted edits, `.git/config` and hooks are not touched,
and the agent's git config and hooks are never carried over. Review and merge it
with git as you would a colleague's branch. Changes in `~` stay in the session, and
a queued push is left to you: the work is on the new branch now.

## Policies

`airbag.yaml` in the repository (and `~/.config/airbag/airbag.yaml`) adds hosts and
rules. Rules are [CEL](https://cel.dev) expressions over effects. Some effects are
observed, so a rule holds whatever program causes them: every connection passes
the proxy (`net.connect`), every secret read passes FUSE. Others are predicted from
a command line by built-in models (`net.egress` for `curl -d`, `fs.delete` for
`rm`): a rule on those refuses early and marks the review, but a script can do
more than its command line shows, so for them the sandbox and the review are the
boundary.

```yaml
allow: [api.github.com]
rules:
  - name: ask-before-sending
    when: effect.kind == "net.egress"        # curl -d, scp, npm publish, ...
    verdict: ask
    message: data leaves the machine
  - name: never-prod
    when: command.line.contains("--context prod")
    verdict: deny
```

Rules can also read the session's labels, `session.labels`: `secret` once
the session read a secret file, `untrusted` once it pulled content from a web
host. That keeps outside input from driving an irreversible effect:

```yaml
  - name: no-push-after-web
    when: '"untrusted" in session.labels && effect.kind == "intent.git_push"'
    verdict: deny
```

Rules are type-checked when airbag starts: a misspelled field (`effect.knd`) is an
error, not a rule that never matches. A `deny` or `ask` rule that fails while
evaluating (say `command.argv[0]` on an effect with no command) counts as
matched, and the message says so; guard such rules with `command.argv.size() > 0`.

Verdicts are `allow`, `deny` and `ask`; a deny anywhere wins. An `ask` blocks the
command and tells the agent to have you run `airbag approve a-N`; after that the
retry passes. For Claude Code the answer arrives through a PreToolUse hook, before
the command runs; Codex gets the same through its hooks. The repository's file is read from the real workspace, so the
agent cannot loosen its own rules, and a change to it shows up in review as
`persist`.

### Deferred commands

A command that acts on the world with your credentials, such as opening a pull
request or publishing a package, fails in the sandbox: the agent has neither the
token nor the network for it. `defer:` lets such calls wait in the outbox instead:

```yaml
defer:
  - gh pr create
  - gh release create
  - npm publish
```

Each entry is a program and the words that pick its calls: `gh pr create` holds
`gh pr create --title x` and `gh -R org/repo pr create`, while `gh pr list` runs
in the sandbox as before. airbag puts a shim for the program first in the agent's
PATH. The agent gets `queued as intent i-N` and carries on; review lists the call
with the files it names. A call by full path (`/usr/bin/gh`) skips the shim and runs
in the sandbox, so `defer:` is a convenience: the boundary is still that the agent
holds no credentials.

The command runs on your machine, with your environment and credentials, after
`airbag apply` has written the files:

- you confirm each one; `--yes` does not run them;
- the program comes from your PATH, never from the workspace;
- files it names in the workspace must hold what they held when it was queued,
  and a file outside the workspace is refused when the agent queues the call
  (`/tmp` in the sandbox is not yours); pass text inline or put the file in the
  workspace; a call that names a secret file (`.env`, a key) is refused, and so is
  one that names the session's own storage;
- while links the session put in your files lead out of the workspace or to a
  secret file (`notes.md -> .env`, `docs -> ~/.config`, a venv's interpreter in
  `~/.local`), the commands wait, whatever their arguments say: an argument that
  is or runs through such a link would read or write there without showing it.
  Links to installed programs (`/usr/bin/python3`: root's, in root's
  directories) do not count; links to any directory outside, `/usr` included, or
  to a configuration file anyone may read, do. Remove
  or replace the links, or after inspecting them run `airbag apply --trust-links`;
- after a failure the rest wait, since a pull request without its push means
  nothing; after `apply --branch` they all wait, because the working tree is not
  the result; if the session changed `.git/config` or hooks, they wait for
  `--trust-git`, as pushes do, and run with hooks and fsmonitor off;
- rules see the call as an `intent.cmd` effect, so
  `'"untrusted" in session.labels && effect.kind == "intent.cmd"'` can refuse
  it, and review flags a call that carries a value from your secret files.

It reads the workspace as applied, as it would if you ran it yourself after
merging: `npm publish` runs the scripts in `package.json`, `make release` the
`Makefile`. Review those first.

### Credentials

Some tasks need a token to work at all: listing pull requests, reading a private
API. Bind the token to the hosts it is for, in your own
`~/.config/airbag/airbag.yaml` (a repository's `airbag.yaml` cannot, since it
would decide where your tokens go):

```yaml
credentials:
  - name: github
    hosts: [api.github.com, uploads.github.com]
    source: command:gh auth token      # or env:GH_TOKEN, or file:~/.config/x/token
    env: [GH_TOKEN]
```

The agent sees `GH_TOKEN` set to a placeholder of the same shape (`ghp_` and
random characters). For the bound hosts, and only for them, airbag terminates
TLS with a certificate authority made for the session: its key stays in
airbag's memory, and its name constraints permit only those names (and the
names under them) and no name of the other kind (no IP address when the hosts
are names, no DNS name when they are addresses), so a verifier that checks
constraints, as Go and OpenSSL do, accepts it for no other site. Its
extended key usage is TLS server authentication only. airbag
replaces the placeholder with the value in the request's
headers (Basic credentials included) and query, checks the real host against this
machine's roots, and replaces the value with the placeholder in the response, so a
host that echoes the request does not hand the token to the agent. A request whose
`Host` names another site is refused, so a server that hosts several sites (a CDN)
cannot be asked to route the token to one the binding does not name (domain
fronting). The value is
read when the session starts and is never written to disk. Tools in the sandbox
trust the session's authority through `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` and
the like.

Because airbag sees these requests, review lists each one with its method and
path, and rules can match them as `http.request` effects:

```yaml
rules:
  - name: github-read-only
    when: effect.kind == "http.request" && effect.target.startsWith("api.github.com/") && effect.detail != "GET"
    verdict: deny
    message: reads only; open the pull request with `defer:`
```

The agent can do with the token whatever the token allows on those hosts,
right away: bind a token with the least scope that does the job, and use rules or
`defer:` for writes. After a secret read the bound hosts are cut off like any host
that is not a model API. Not covered: tokens in request bodies (OAuth flows),
tools that pin certificates or keep their own trust store (Java), Go programs on
macOS whose `go.mod` declares a Go version before 1.27, most Go tools today (they
ignore `SSL_CERT_FILE` whichever Go builds them), and Node's built-in `fetch`, which ignores
`HTTPS_PROXY` unless `NODE_USE_ENV_PROXY=1` (Node 22.21 and later). A protocol
upgrade (a websocket) to a bound host is refused: airbag could not keep the
value out of the upgraded stream.

Which tools an agent may call is the agent's own setting (Claude Code's
permissions, Codex's configuration), and airbag does not duplicate it. airbag
governs the effects any tool has: files, network, processes and secrets.

## Install

```console
$ curl -fsSL https://raw.githubusercontent.com/getjump/airbag/main/install.sh | sh
$ airbag doctor
```

The script installs the latest release for Linux or macOS 13 and later (amd64,
arm64) into `~/.local/bin` after checking its SHA-256 against the release. Or
from source, with Go 1.27.1 or newer:
`go install github.com/getjump/airbag/cmd/airbag@latest`.

With Nix: `nix run github:getjump/airbag -- doctor`, or add the flake's
`packages.<system>.airbag` to your configuration. `nix flake check` runs the unit
tests, `nix develop` gives a shell with Go and the test tools.

One static binary, no daemon, no Docker. Needs Linux 5.12+ with unprivileged user
namespaces. On Ubuntu 23.10+ AppArmor restricts them; `airbag doctor` prints the
one-time profile to install. On macOS there is a native prototype (Seatbelt
around the agent, an APFS clone as the branch), not yet tried on a real Mac, and the
Linux VM setup that works today; see [docs/macos.md](docs/macos.md).

## Status

Early v0, not yet tried by anyone outside the project. Working on Linux: sandbox,
branch, proxy with allowlist and address checks, mirror, outbox for git push and
`defer:` commands, review (text, `--attention`, `--json`), diff, apply with conflict
check (all or nothing), `apply --branch`, `rollback`, `run --session`, `tcp://`
forwards, credentials through placeholders, discard. On macOS: a prototype (see above). Claude Code gets airbag's hooks as
read-only managed settings, Codex as a read-only `/etc/codex/requirements.toml`
(unless the host has its own), so the review shows which tool call changed which
file. Codex's own SQLite state folds into one review line.
`bash` and `sh` are shimmed: each `-c` script is parsed, every command is matched
against a model of its effects (`rm -rf` deletes, `curl -d` sends data out, `git
config core.hooksPath` persists), and known secret values (from `.env` and
credential-like variables) are masked in its output. The models are predictions
for review and early refusals; scripts and programs they do not cover are
`opaque`, and the boundary for those is the sandbox, the proxy and FUSE.

Tests: `go test ./...`, then as a regular user every `test/*e2e.sh` and
`python3 test/ctrlc.py` (CI runs them on each push); `test/claude-e2e.sh` and
`test/codex-e2e.sh` drive the real Claude Code and Codex binaries against
`test/mockapi`, a scripted mock of the Messages and Responses APIs. With a real login, follow [docs/manual-test.md](docs/manual-test.md).

Each session keeps one SQLite database, `effects.db`: the effect log and the
outbox, with the history of every intent's status. Triggers make all of it
append-only, so `sqlite3` answers questions the review does not.

Not yet: passing Codex's SQLite state through (transcripts in `~/.codex/sessions`
survive a discard, its thread index and memories do not), and pins from
`pnpm-lock.yaml`, `poetry.lock` and hashed requirements files for the mirror after a
secret read. Tools that ignore the mirror settings cannot reach registries;
`--allow HOST` opens one directly.

Deliberately left for later, each with the reason and what would bring it back
([docs/roadmap.md](docs/roadmap.md)): placeholders in `.env` files, TLS termination
for model APIs, data flow labels per value, syscall-level control, savepoints per
tool call.
Before more features comes a measurement on real work against the alternatives:
[docs/evaluation.md](docs/evaluation.md).

## Threat model

airbag protects against accidents and casual exfiltration by an agent you let run
without prompts. It is not a VM: the kernel is shared, and whatever the agent reads
is still sent to the model API. A bound credential keeps its value from the agent,
not its use: through the bound hosts the agent can do what the token allows.

The seccomp filter removes the parts of the kernel surface an agent has no reason
to touch (above), which cuts the exposure an unprivileged-user-namespace escape
would use; but the kernel is still shared, so it is a smaller target, not a VM
boundary. `airbag doctor` reports the host sysctls that harden the rest, and
where the host sends core dumps.

For hosts without a credential the proxy decides from the name the client asks for
and does not see inside TLS. So a broad allowlist entry (`github.com`) is a way for
data to leave, and domain fronting can reach a site behind the same CDN that the
allowlist does not name. Allow narrow names, and where that matters put an `ask`
rule on `net.connect` for the broad ones: every connection passes it, while
`net.egress` is predicted from known command lines only.

The proxy, the forwards and the control socket run in airbag's process on the
host and parse what the agent sends. airbag closes the connections there that
stop carrying data (a request header must arrive within 30 seconds at the
proxy and 10 at the control socket; the other bounds are
[above](#what-the-agent-gets)). A refusal the proxy answers before it relays
anything (outside an intercepted connection, whose refusals close with its idle
limit) is the last answer on its connection, and closes it if the agent does not
read it within 30 seconds. An answer from the mirror that the agent stops reading
closes the connection too: each 64 KiB of it must go out within 30 seconds, and
the socket takes more only once the agent has read most of what it holds (about
200 KiB on Linux), so a reader slower than a few KiB a second is cut off as well.
airbag caps the tunnels, the forwarded connections and the connections to the
proxy and to the control socket a session holds at once. Each refusal (a deny,
or an ask) is a row in the effect log on the host's disk: past a burst of 1000,
refusals of one kind are logged at most 50 a second, and review counts the rest. A connection that keeps moving bytes stays open as long as it does, and
bandwidth and the rate of new connections are not limited.

## License

Apache-2.0
