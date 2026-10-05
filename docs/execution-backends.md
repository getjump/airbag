# Execution boundaries

`airbag capabilities --json` describes the backend compiled into the binary.
It does not probe the machine or attest a running session. `airbag doctor`
checks host prerequisites. `airbag run` records the selected backend,
isolation boundary, egress and explicit requirement in session metadata.

Egress is `allowlist-proxy` unless the session has a path around the proxy,
named after it: `+nix-daemon` on Linux for a session started with
`--nix-daemon` (the daemon's builds and substitutes reach the network; macOS's
profile allows no Nix socket), and `+tcp-forward` for `--allow tcp://HOST:PORT`
(on Linux airbag dials HOST:PORT from the host, policy-checked and logged; on
macOS the agent connects to a port on this machine directly). HiddenHost is
fixed when the session is created; a resume can add forwards. `run` prints
backend, isolation and egress when one of them is not the default: another
backend, a requirement, or a path around the proxy.

Only `--backend=native` is implemented. Linux uses namespaces, overlayfs and
seccomp; macOS uses Seatbelt and a workspace clone. Both share the host
kernel. macOS has no HOME branch. Linux's HOME branch can be disabled with
`--no-home`; the capability describes support, not an individual session.

```sh
airbag capabilities --json
airbag run --backend=native --require-isolation=shared-kernel -- claude
airbag run --require-isolation=virtual-machine -- claude # refused before session creation
```

The named boundaries are `shared-kernel`, `application-kernel`, and
`virtual-machine`. They describe mechanisms, not a universal security ranking.
`any` is the default: accept the selected mechanism. A requirement names an
exact boundary. Unknown names, unavailable backends and unmet requirements
fail closed; installing runsc or Firecracker does not silently activate them.
Resume checks saved requirements before modifying the branch or run state.
Legacy sessions without these fields remain native sessions.
`test/isolation-e2e.sh` checks both refusals, the egress a session records
and `capabilities --json` through the installed CLI.

## Responsibilities across future backends

The execution backend owns starting, isolating, stopping and exporting a
workspace. The host owns policy decisions, real service credentials,
approvals, durable effect requests/results and importing reviewed changes.
These responsibilities are a design constraint for an implementation, not a
claim that a microVM backend exists today.

An application kernel or guest kernel does not enforce semantic API scope.
For example, a token permitted to reach GitHub may still modify an unintended
repository. Conversely, a scoped effect request does not protect the host
kernel from arbitrary code. Both boundaries matter.

Before adding a backend, verify workspace/HOME semantics, package/build
compatibility, forced egress, terminal and signal handling, resource limits,
stopping every descendant, secret mediation, audit coverage and safe export.
Guest-reported telemetry is not authoritative after guest compromise. Keep
policy and credential/stop authority outside the guest and validate exported
data at that boundary. Missing support must reject a requested feature, not
silently remove it.

## Current limits

- Native execution exposes a shared host kernel to agent code.
- Allowed destinations can receive agent data and perform remote effects.
- `--nix-daemon` (Linux) and `tcp://` forwards open egress outside the proxy.
- Agent-state passthroughs can survive discard.
- Credential placeholders do not issue short-lived credentials or restrict
  the real token's service-level scopes.
- Secret taint restricts egress; it is not a general process kill switch.

Typed external effects ([effect-contract.md](effect-contract.md),
[typed-pr-outbox.md](typed-pr-outbox.md)) and runtime FUSE/exec policies
(PR #9) are separate from this report and must not be inferred from it.
