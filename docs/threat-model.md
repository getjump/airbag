# Threat model

airbag protects against accidents and casual exfiltration by an agent you let run
without prompts. It is not a VM: the kernel is shared, and whatever the agent reads
is still sent to the model API. A bound credential keeps its value from the agent,
not its use: through the bound hosts the agent can do what the token allows.

The seccomp filter removes the parts of the kernel surface an agent has no reason
to touch ([Terminal and kernel](agent.md#terminal-and-kernel)), which cuts the
exposure an unprivileged-user-namespace escape would use; but the kernel is still shared, so it is a smaller target, not a VM
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
