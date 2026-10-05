# Security policy

airbag limits what a coding agent can do to your machine. A way for the agent
to get past that limit is the report that matters most.

## Reporting a vulnerability

Report it privately through GitHub:
**[Report a vulnerability](https://github.com/getjump/airbag/security/advisories/new)**
(GitHub's private vulnerability reporting, on the Security tab). Please do not
open a public issue, pull request or discussion about it, or post it
elsewhere, until a fix is out.

A report helps most when it has:

- the airbag version (`airbag version`) and the output of `airbag doctor`;
- the OS, the kernel and the agent, with their versions;
- the policy files in use and the `airbag run` flags;
- what the agent runs, and what you then see on the host;
- which promise in the README or the docs it breaks.

One problem per report. Reproduce it yourself first, and if a tool helped you
find it or write it up, say so. A report we cannot reproduce, or one about code
that does not exist, is closed.

## What to expect

airbag has one maintainer, so these are the times we can keep:

- an acknowledgement within 7 days;
- an update at least every 14 days until the report is fixed or closed;
- coordinated disclosure within 90 days of the report. If a fix needs longer,
  we agree on the date with you.

If 7 days pass with no answer, open a public issue that asks us to look at the
advisory, with no details in it.

We fix it in private, publish a GitHub security advisory that names the fixed
version, request a CVE through GitHub when the problem is in scope, and credit
you unless you would rather not. airbag is a command, not a library: watch the
repository's releases and security advisories to hear about fixes.

## Supported versions

airbag is at 0.x. Fixes go into the latest 0.x release; older releases get
none. Until the first release is tagged, that is `main`.

## What counts as a vulnerability

The agent doing what airbag says it cannot. With a default or documented
configuration, an agent under `airbag run` that can:

- change your files or `$HOME` before `airbag apply`, other than the agent
  state the README says passes through, or run code on the host before you
  approve it;
- read what airbag hides: credential files and variables, host sockets, a
  bound credential's real value, or airbag's own memory and environment;
- reach a host the allowlist and policy do not allow, including this machine,
  link-local or a cloud metadata address through an allowed name, or, after a
  secret read, reach what the read cuts off;
- read a watched secret file without the session being labelled `secret`;
- loosen the policy it runs under;
- get a `git push` past the outbox, or make `airbag apply` write something
  `airbag review` did not show;
- push input into the terminal you return to;
- make a syscall, or open a socket family or netlink protocol, that the README
  says the seccomp filter refuses;
- crash airbag's process on the host, or hold more there than the bounds the
  README states, through the proxy, the forwards, the mirror or the control
  socket.

A way to change a release that reaches users (the binaries, `SHA256SUMS`,
`install.sh` or the release workflow) is in scope too.

## What does not

The limits airbag documents are not vulnerabilities, unless they also break a
promise the docs make elsewhere:

- airbag is not a VM. The kernel is shared, so a kernel bug the sandbox can
  reach is a kernel bug: report it upstream. A call the README says the filter
  refuses that gets through is in scope, above.
- What the agent reads is sent to the model API. Its own file tools are not
  filtered, so a secret it reads can reach its model.
- What the policy allows: an allowed host used to send data out, a bound token
  used on its hosts, `--allow`, `--pass-env`, `--nix-daemon`.
- The rest of the README's [threat model](README.md#threat-model): the proxy
  decides by the name the client asks for and does not see inside TLS, so a
  broad allowlist entry and domain fronting are ways out; bandwidth and the
  rate of new connections are not limited.
- The gaps the README names: the two of the default mode that `--strict`
  closes, and the one it leaves when airbag runs as root; a socket
  `core_pattern`; a `defer:` command called by its full path.
- Command models are predictions. A script they read as `opaque` is not a
  bypass; the sandbox, the proxy and FUSE are the boundary for it.
- On the macOS prototype, the limits [docs/macos.md](docs/macos.md) lists.
- Prompt injection of the agent itself.
- Hardening ideas with no way past the boundary shown. Open a public issue for
  those.
