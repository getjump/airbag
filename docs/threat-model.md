# Threat model

airbag protects against accidents and casual exfiltration by an agent you let run
without prompts. By default it is not a VM: the native backend shares the host's
kernel (the experimental `--backend=microvm` boots a guest kernel instead, below),
and whatever the agent reads is still sent to the model API. A bound credential keeps its value from the agent,
not its use: through the bound hosts the agent can do what the token allows.

The seccomp filter removes the parts of the kernel surface an agent has no reason
to touch ([Terminal and kernel](agent.md#terminal-and-kernel)), which cuts the
exposure an unprivileged-user-namespace escape would use; but with the native
backend the kernel is still shared, so it is a smaller target, not a VM boundary. `airbag doctor` reports the host sysctls that harden the rest, and
where the host sends core dumps.

`airbag capabilities [--json]` describes the compiled execution boundary.
The native backend, the default, shares the host kernel. Linux can also use
experimental `--backend=gvisor` or `--backend=microvm`: an isolated workspace
profile with the same host policy, proxy and outbox ([runtime
options](runtime-options.md): prerequisites, what they reject, real-provider
validation). `run --require-isolation=virtual-machine` refuses to run instead of
falling back. See [execution boundaries](execution-backends.md).

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
[under Network](agent.md#network)). A refusal the proxy answers before it relays
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

## WSL2

airbag has no Windows backend; under WSL2 the Linux build runs the Linux
sandbox on WSL's kernel. The new boundary WSL adds is interop with the Windows
host, and a Windows process a sandboxed agent could start would run as the user
outside every Linux boundary airbag sets up. That channel is closed:

- **Interop is unreachable.** WSL registers a binfmt_misc handler (`WSLInterop`)
  that matches the PE `MZ` magic and hands the file to `/init`, which asks the
  Windows side to launch it over the Unix socket named in `WSL_INTEROP` (under
  `/run/WSL`). The sandbox makes `/run` a private tmpfs, so that socket is not
  there; and airbag drops `WSL_INTEROP` and `WSLENV` from the agent's
  environment and strips the `/mnt/<drive>` Windows-PATH entries, so neither the
  socket, the env bridge, nor a path to `cmd.exe`/`powershell.exe` reaches the
  agent. A PE run by any route (absolute path, a copy into the workspace that
  the binfmt match would catch, `/init` directly) finds no live interop socket
  and does not reach Windows. `test/wsl-interop-e2e.sh` exercises each route and
  asserts no Windows-side effect, with a positive control outside the sandbox.
- **`/mnt/c` is read, not write.** The Windows drives are drvfs mounts; the
  recursive read-only remount of the host covers them, so a write to `/mnt/c`
  fails as anywhere else on the host. Reads are not blocked: as on Linux,
  whatever the agent reads can reach its model, so Windows files under `/mnt/c`
  are as exposed as the rest of a readable host. Keep the workspace and
  secrets on the Linux filesystem (`~`), not under `/mnt/c`.
- **The Windows host network is unreachable.** The sandbox has only loopback
  and the proxy, so the WSL gateway and the resolv.conf nameserver (the Windows
  side) are not reachable from inside; traffic still leaves only through the
  proxy and its allowlist.
- **Supported workspace locations.** The Linux filesystem. A workspace under
  `/mnt/c` is a Windows path: it is read-only in the sandbox and outside
  airbag's branch-and-apply model, so airbag does not support it.

WSL2 is tier 3 ([support.md](support.md)): built from source, checked by an
informational CI job, with no release promise.
