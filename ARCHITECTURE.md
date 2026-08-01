# Architecture

quic-link is a single Go binary that acts as both a **client-side owner process** and a **server-side agent**, multiplexing named services — SSH, Docker, and more to come — over one mutually-authenticated QUIC session. There are no CA files; authentication is mandatory Ed25519 public-key pinning. One binary, two roles selected by config.

---

## Two roles, one binary

Which role the process plays is determined entirely by its configuration file:

| Role | Activated by | What it does |
|---|---|---|
| **Owner** (client) | A `[servers.*]` block | Dials the agent(s), holds a session pool, and binds local TCP ports plus a unix socket for short verbs. `quic-link daemon [--server NAME]` is the one owner verb; it runs in the foreground and expects a service manager (systemd user unit, launchd agent, shell `&`) to background it. `quic-link connect [SERVER]` is a hidden, deprecated alias for `daemon --server SERVER` and will be removed in a future release. Exactly one owner runs at a time — the unix socket is the lock. |
| **Agent** (server) | An `[agent]` block | Listens for the owner's QUIC connection, maintains a route table of named targets, and dials the real local service for each stream. |

The same binary handles both, so upgrading is always an atomic event: build once, deploy to both ends.

---

## The connection model

- **One QUIC session per configured server.** The owner dials eagerly at start and reconnects on drop; there is no "connect on first use" lazy path.
- **Multiplexed streams.** Every service interaction (an SSH login, a Docker API call) is a separate QUIC stream inside the single session. Streams are opened cheaply with no new handshake.
- **One control stream per session.** The very first stream the owner opens is a gRPC-over-QUIC control channel. It carries the `Ping` RPC (used by the `ping` verb) and doubles as the session's heartbeat — if it closes, the session is torn down and reconnected. `quic-link status --json` is answered separately, over the owner's local unix socket, not this control stream.
- **Logical targets, never raw addresses.** Every data stream opens with a short header naming a *logical target* (e.g., `"ssh"`, `"docker"`). The agent's route table is the sole resolution and authorization boundary. No client ever names a raw `ip:port`.

**Why QUIC?** Three reasons that matter for correctness: (1) streams are independent under packet loss, so a stalled Docker image pull cannot block keystrokes; (2) stream half-close (`FIN`) and reset (`RST`) are first-class QUIC concepts, so they can be faithfully relayed across the tunnel; (3) TLS 1.3 is built in, so there is no separate encryption layer to manage.

---

## Life of a byte

Tracing one SSH connection from a terminal through the full stack:

```
1.  Terminal          ssh -p 50330 user@127.0.0.1
2.  Local edge        the daemon's edge accept-loop accepts the TCP connection
                      on the bound port for this server's "ssh" target
3.  Header stamp      the edge opens a new QUIC stream on the pooled session and
                      writes a header first: { kind: "tcp", target: "ssh" }
4.  Agent router      agent reads the header, checks the target is in the route table
                      and authorized, then dials tcp://127.0.0.1:22
5.  Response frame    agent sends back { status: 0, msg: "ok" } on the stream
6.  Splice (×2)       bytes flow bidirectionally:
                        local TCP conn ↔ QUIC stream ↔ sshd TCP conn
                      half-close on one side becomes a stream half-close on the other;
                      an error becomes a QUIC stream reset — never converted
7.  Return path       sshd's reply retraces steps 6 → 5 → 4 → 3 → 2 → 1
```

The ssh/Docker local ports splice directly inside the daemon process — no unix
socket round trip. The unix socket (`internal/ipc`) is a separate path used by
short-lived CLI verbs that are not raw TCP clients: `status` asks the daemon for
a session snapshot, and `stdio` asks it to open one stream on the pooled session
and hand back a connection to splice against stdin/stdout. Both paths converge
on the same `tunnel.DoAttach` splice primitive so the wire behaviour is
identical either way.

---

## Package map

| Package | Responsibility | Key dependencies |
|---|---|---|
| `cmd/quic-link` | CLI entry point; cobra command tree; thin verb wrappers; maps typed errors to exit codes | all internal packages |
| `internal/proto` | QUIC wire protocol v1: length-prefixed CBOR frames, `Header`/`Response` types, status codes, test vectors | `fxamacker/cbor/v2` |
| `internal/transport` | `Transport`/`Conn`/`Stream` interface seam; QUIC implementation; `transport/mem` in-memory implementation for tests | `quic-go` (QUIC impl); nothing (interface seam) |
| `internal/identity` | Ed25519 key generation and loading; pin derivation (`base64(SHA-256(SPKI))`); pinning TLS config builders | stdlib `crypto/`, `crypto/x509` |
| `internal/config` | TOML config loader; `flags > env > file > defaults` precedence; role-scoped semantic validation | `pelletier/go-toml/v2` |
| `internal/router` | Agent-side route table: named targets → `tcp://` or `unix://` addresses; allow-all authorization call-site | `internal/proto` |
| `internal/tunnel` | Bidirectional byte splice (`Pipe`, `DoAttach`); agent `Serve` loop; the shared `OpenControl` helper that classifies an auth rejection identically for every caller (daemon pool, `ping`, `stdio`) | `internal/proto`, `internal/transport`, `internal/router`, `internal/control` |
| `internal/control` | gRPC control stream over QUIC: `Ping` RPC (`GetStatus` reserved, not yet implemented); net.Conn adapter over a `transport.Stream` | `google.golang.org/grpc`, `internal/transport` |
| `internal/ipc` | Unix socket IPC frame set (framed CBOR); socket server and client; `StatusProvider` and `AttachPool` interfaces | `internal/proto`, `fxamacker/cbor/v2` |
| `internal/daemon` | Lifecycle, session pool (`dialEntry` — the single dial-and-classify implementation, one reconnect loop), status snapshot, signal-driven shutdown; orchestrates ipc + tunnel | `internal/config`, `internal/ipc`, `internal/transport` |
| `internal/edge` | Local TCP listeners the daemon binds and holds for each server's targets (ssh, docker); accept-loops splice directly via `tunnel.DoAttach` | `internal/config`, `internal/tunnel` |
| `internal/probe` | `ping` verb: handshake timing + RTT sampling (RFC 9002 connection stats) | `internal/transport`, `internal/control` |

---

This file, together with `README.md` (what it does, how to use it) and
`CONTRIBUTING.md` (how to build, test, and report issues), is the complete
entry point for anyone reading only the tracked repository.

---

## Key invariants

Six rules that every contributor must internalize. These are encoded in the code's design; violating one silently breaks a contract visible to operators or users.

1. **Clients name logical targets, never raw `ip:port`.** Every data stream carries a target name like `"ssh"` or `"docker"`. The agent's route table translates and authorizes. The client never decides where to dial on the remote host.

2. **Authentication is mandatory — there is no unauthenticated path.** Both ends must present a pinned Ed25519 key. The agent requires at least one authorized-client pin to start. There is no debug mode, no loopback exemption, no optional flag that disables mutual auth.

3. **Half-close propagates as half-close; reset propagates as reset.** A `FIN` from one side of a splice becomes a QUIC stream half-close (`CloseWrite`), not a full close. An error becomes a QUIC stream reset. Protocols like `scp`, `git clone`, and HTTP/1.1 depend on this distinction.

4. **The QUIC wire protocol is versioned.** Any change to frame layout, field semantics, or status codes bumps `ProtoVersion` and the ALPN negotiation string. A mismatch fails at the TLS handshake — both ends must be rebuilt together. Never extend the protocol informally.

5. **The `status --json` byte-shape is a locked contract.** Scripts and monitoring tools consume this output. Adding a field, renaming a key, or changing an enum value requires an explicit `schema` bump and a golden-file update. Do not drift the output silently.

6. **No privileged operation happens at runtime.** Capability grants, loopback aliases, and resolver registration belong only in a future `quic-link init` step, with explicit operator consent. The daemon, `connect`, and `ping` verbs never call `sudo`, never request elevated capabilities at runtime, and degrade gracefully when optional capabilities are absent.

---

## Running the tests

See `CONTRIBUTING.md` for the exact commands and the full PR gate.
