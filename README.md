# quic-link

quic-link is a single binary — a client-side **daemon** and a server-side
**agent** — that multiplexes named services over one mutually-authenticated
QUIC session. Each end holds a key and pins the other's public key during the
handshake.

**Status:** core tunnel is complete (framed protocol, SSH + Docker routes, pinned
identity, TOML config). A client-side daemon manages sessions and exposes a
`status` command over a local socket; a loopback naming layer and job runners
are in progress.

## Quickstart

**Prerequisites**

```bash
go mod tidy   # one-time, from inside the module directory
```

**1. Generate an identity on each host (one-time)**

Authentication is mutual raw-public-key pinning: each host holds an Ed25519 key
and the two ends verify each other's *pin* — `base64(SHA-256(public key))` —
during the QUIC handshake. There are no CA files.

```bash
# On BOTH the agent host and the client host:
quic-link keygen
# -> pin: <base64>      (key written to ~/.config/quic-link/key.pem)
```

Note each host's pin and **exchange them out of band**. `keygen` is idempotent,
reprints the existing pin. `keygen --force` rotates the key (peers must re-pair
with the new pin).

**2. On the agent host** (UDP port 443 must be open)

```bash
quic-link agent \
  --listen :443 \
  --authorized-client <client-pin>
```

`--authorized-client` is repeatable; at least one pin is required (the agent
refuses to start with an empty set). The built-in `ssh` route already defaults
to `tcp://127.0.0.1:22`; override it with `--ssh-addr` if sshd listens
elsewhere. `--docker-addr` overrides the Docker socket (default
`unix:///var/run/docker.sock`). `--route NAME=ADDR` (repeatable) adds any
further route, for example `--route pg-app=tcp://127.0.0.1:5432`.

**3. On the client, describe the server in a config file**

The client is config-driven: write `~/.config/quic-link/config.toml` (see
[Configuration file](#configuration-file) below) naming the agent's address and pin:

```toml
schema = 1

[servers.myserver]
addr = "myserver.example.com:443"
pin  = "<agent-pin>"
```

**4. Run the daemon**

```bash
quic-link daemon --server myserver
```

The daemon dials the agent, prints `connected to server`, and holds two local
TCP ports open for the lifetime of the session — one for SSH, one for Docker.
The ports are derived deterministically from the server name (so they are the
same on every run) unless overridden with `local_ports` in the config. Find
them with `status`:

```bash
quic-link status --json
# {"schema":1,...,"servers":[{"name":"myserver","session":"connected",
#  "local_ports":{"ssh":50330,"docker":50331},...}]}
```

Use them in another terminal:

```bash
ssh -p 50330 user@127.0.0.1
docker -H tcp://127.0.0.1:50331 ps
```

Running `quic-link daemon` a second time while one is already active exits
with code 3 — only one daemon owns the local socket at a time.

**5. Ping**

```bash
quic-link ping myserver --count 5
```

`ping` reads the server's address and pin from the same config file. A wrong
pin on either end fails the handshake and exits with code 4 (auth failure);
the message names the mismatched pin.

## Build and test

```bash
go build ./...
go test ./...
```

## Architecture

```
cmd/quic-link/        CLI + subcommands (keygen, agent, daemon, status, ping)
internal/proto/       framed protocol (CBOR types, status codes, test vectors)
internal/transport/   QUIC transport abstraction (+ in-memory impl for tests)
internal/identity/    Ed25519 keys, pins, raw-public-key pinning TLS
internal/router/      agent route table (named targets → tcp/unix) + authorization
internal/tunnel/      stream ↔ TCP/unix splice (agent + daemon sides)
internal/control/     gRPC control stream over QUIC (ping RPC)
internal/config/      TOML config loader (flags > env > file > defaults)
internal/probe/       ping: handshake timing + RTT (RFC 9002)
internal/daemon/      client-side daemon lifecycle, session pool, status snapshot
internal/ipc/         local unix-socket protocol between CLI commands and the daemon
internal/edge/        local TCP listeners the daemon binds and holds for each server
```

`daemon` is the current name for the client-side process; `connect` still
works as a deprecated alias and will be removed in a future release.

---

## Cross-platform notes (Linux & macOS)

### Binding UDP port 443

Ports below 1024 require elevated privileges on Linux and macOS.

- **High-port workaround:** `--listen :4443` (no privilege needed).
- **Linux** (preferred over root): `sudo setcap 'cap_net_bind_service=+ep' ./quic-link` — no macOS equivalent; use a high port or `sudo`.

### UDP receive buffer

quic-go warns if it can't raise the UDP receive buffer to ~7 MB (perf advisory — tunnel still works). Raise it: **Linux** `sudo sysctl -w net.core.rmem_max=7340032 net.core.rmem_default=7340032` (add to `/etc/sysctl.conf` to persist); **macOS** `sudo sysctl -w kern.ipc.maxsockbuf=7340032`.

### macOS Local Network permission (macOS 15 Sequoia and later)

macOS 15+ silently drops unicast traffic to LAN addresses (`192.168.x`, `10.x`)
until the responsible app is granted **Local Network** access. Symptom:
`daemon`/`ping` to a LAN agent times out with `timeout: no recent network
activity` even though the network is fine.

- Grant your terminal (Terminal, iTerm, VS Code) under **System Settings →
  Privacy & Security → Local Network**, then re-run.
- Running under `sudo` bypasses the check — useful to confirm this is the cause.

---

## Configuration file

Reads `~/.config/quic-link/config.toml` by default (`--config PATH` to override). Precedence: CLI flags → `QUIC_LINK_*` env vars → file → built-in defaults. Unknown keys are a startup error; changes take effect after a restart.

### Client (`daemon` / `ping`)

```toml
schema = 1

[servers.myserver]
addr = "myserver.example.com:443"    # agent host:port
pin  = "<agent-pin>"                 # from 'quic-link keygen' on the agent

# Optional:
# enabled     = true
# local_ports = { ssh = 2222, docker = 2375 }
```

### Agent

```toml
schema = 1

[identity]
key_file          = "~/.config/quic-link/key.pem"
warn_key_age_days = 180   # rotation reminder after N days (0 = off)
refuse_old_key    = false # refuse to start with an over-age key

[agent]
listen             = ":443"
authorized_clients = ["<client-pin>"]

# Optional route overrides:
# [agent.routes]
# ssh    = "tcp://127.0.0.1:22"
# docker = "unix:///var/run/docker.sock"
```

### Logging

```toml
[log]
level  = "info"   # debug | info | warn | error  (env: QUIC_LINK_LOG_LEVEL)
format = "text"   # text | json                  (env: QUIC_LINK_LOG_FORMAT)
```
