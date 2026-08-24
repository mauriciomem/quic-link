# Architecture

*This page is meant to be kept reasonably current, but it
might drift a little behind the code. If something here does not match what you see,
the CLI's own `--help` output is the final word.*

quic-link is a single binary that acts as both a **client-side daemon** and a
**server-side agent**, carrying SSH, Docker, and other TCP-ish traffic over one
mutually-authenticated QUIC connection. There are no CA files: authentication is
mandatory Ed25519 public-key pinning. One binary, two roles, selected by config.

## The problem it solves

Reaching a remote machine's SSH and Docker daemon usually means either opening
several ports through a firewall, standing up a VPN, or hand-editing SSH config and
Docker's `DOCKER_HOST` on every machine you use. quic-link replaces all of that with
one authenticated connection: one port open on the remote side, one small config
file on the client side, and normal `ssh`/`docker` commands pointed at a local port
quic-link holds open for you.

## Two roles, one binary

Which role a running process plays is decided entirely by its configuration:

| Role | Activated by | What it does |
|---|---|---|
| **Daemon** (client) | A `[servers.*]` block | Holds the session open and binds local TCP ports (plus a local socket for short-lived commands like `status`). This is the process you run on your own laptop or workstation. |
| **Agent** (server) | An `[agent]` block | Keeps a table of named local services (`ssh`, `docker`, anything else you add) and connects to the real local service for each request. This runs on the remote machine. |

The same binary handles both roles, so upgrading is always a matched pair: build
once, deploy the new binary to both ends.

## Reverse mode

By default the daemon connects to the agent, so the agent needs an address you can
reach — a public one, or a forwarded port on a router you control. Often there is
no way to give it one: it may sit behind carrier-grade NAT, where the ISP shares
one address among many customers and there is nothing to forward, or on an office
network you do not administer.

Reverse mode turns the connection around. The daemon waits, the agent connects out
to it, and **only one end ever has to be reachable — this is how you choose which
one.** Outbound connections work from nearly anywhere; inbound ones often do not.

Only the direction changes. The agent still serves `ssh` and `docker`, you still
type `quic-link ssh homelab` on the daemon's machine, and once the connection is up
it carries streams both ways regardless of who opened it.

Say a machine at home holds your builds, behind an ISP using carrier-grade NAT, and
your workstation is somewhere you can open one UDP port. Point the agent at the
workstation and have the daemon wait:

```toml
# On the workstation: wait instead of connecting out.
[servers.homelab]
listen = ":17443"
pin    = "<the agent's pin>"
```

```toml
# On the remote machine: connect out instead of waiting.
[agent]
dial               = "workstation.example.com:17443"
authorized_clients = ["<the workstation's pin>"]
```

Everything else is unchanged: authentication is mutual and pin-based in both
directions, the agent still decides which services may be reached, and `ssh`, `fwd`
and `docker-env` behave as before. `status` shows `listening` until an agent
connects.

Four things worth knowing:

- **It moves the reachable port; it does not remove it.** One end must still accept
  a connection. What you gain is choosing which.
- **It is not NAT traversal.** No hole punching, no relay, no third party in the
  path — just which end places the call.
- **Connecting does not confer a role.** Roles come from configuration and are
  checked against key identity, so an end claiming the wrong one is refused.
- **Two waiting servers need different pins**, since an incoming connection is
  identified by its pin and nothing else. Use a port of 1024 or above; lower ones
  need privileges the daemon deliberately does not take (see
  [platform notes](platform-notes.md)).

## The connection model

- **Either end can be the one that connects.** By default the daemon connects to
  the agent, which is what you want when the agent has a reachable address. When it
  does not, you can turn it around, and only the direction of the initial
  connection moves — not who does what. See [Reverse mode](#reverse-mode).
- **One QUIC connection per configured server**, re-established automatically if it
  drops. Whichever end connects is the end that reconnects.
- **Many streams, one connection.** Every SSH login and every Docker API call rides
  its own stream inside that single connection, opened cheaply with no new
  handshake each time.
- **A control channel rides along.** The very first stream carries a small control
  channel used for connectivity checks and as a heartbeat: if it closes, the
  session is torn down and reconnected.
- **The client never names a raw address.** Every request names a logical target
  like `"ssh"` or `"docker"`. The agent's own route table is what decides where
  that actually goes and whether the caller is allowed to reach it. The client
  cannot ask the agent to dial an arbitrary host or port.

**Why QUIC?** Three reasons that matter in practice: streams are independent, so a
stalled Docker image pull cannot block your SSH keystrokes; a clean disconnect and
an abrupt error are both first-class concepts on the wire, so they can be relayed
faithfully instead of being collapsed into "the connection ended somehow"; and
TLS 1.3 comes built in, so there is no separate encryption layer to configure.

## Life of a byte

Tracing one SSH connection from your terminal through the tunnel:

1. **You run** `ssh -p <port> user@127.0.0.1`, using the port quic-link handed you
   for this server (`quic-link status --json` reports it), or simply
   `quic-link ssh <server>`, which looks it up for you.
2. **The daemon accepts** that local TCP connection on the port it is holding open
   for this server's "ssh" target.
3. **A new stream opens** on the existing QUIC connection, carrying a small header
   that says, in effect, "this is a `tcp` request for the `ssh` target."
4. **The agent reads that header**, checks the target exists and the caller is
   authorized, and dials the real local service, `127.0.0.1:22` by default.
5. **The agent replies** with a short "ok" on the same stream.
6. **Bytes flow both ways** from there: your local TCP connection, the QUIC stream,
   and the real `sshd` connection are spliced together. A clean close on one end
   becomes a clean close on the other; an error becomes an error. Nothing gets
   silently turned into the other.
7. **sshd's replies** retrace the same path back to your terminal.

Two client-side paths reach that splice. Long-lived local ports (the ones `status`
reports) splice directly inside the daemon process. Short commands that are not
themselves a raw TCP listener, `status` asking for a snapshot, or a single `ssh`/
`fwd` session opening one stream, go through the daemon's local socket first and
then join the same splice. Either way, the behavior on the wire is identical.

---

This page describes the tunnel's design; it is not a complete list of what ships
today. Some ideas here (a naming layer, more advanced routing) are part of the
project's direction but are not built yet. The `README.md` **Status** line is the
authority on what actually works right now.
