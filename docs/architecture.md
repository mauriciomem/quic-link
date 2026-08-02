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
| **Daemon** (client) | A `[servers.*]` block | Dials the agent, holds the session open, and binds local TCP ports (plus a local socket for short-lived commands like `status`). This is the process you run on your own laptop or workstation. |
| **Agent** (server) | An `[agent]` block | Listens for the daemon's QUIC connection, keeps a table of named local services (`ssh`, `docker`, anything else you add), and dials the real local service for each request. This runs on the remote machine. |

The same binary handles both roles, so upgrading is always a matched pair: build
once, deploy the new binary to both ends.

## The connection model

- **One QUIC connection per configured server.** The daemon dials as soon as it
  starts and reconnects automatically if the connection drops.
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

1. **You run** `ssh -p 50330 user@127.0.0.1` (the port quic-link handed you).
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
