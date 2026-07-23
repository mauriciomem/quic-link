# quic-link — QUIC SSH tunnel (MVP)

`quic-link` is a minimal QUIC tunnel that forwards SSH connections.  
One symmetric binary, two roles (`serve` / `connect`), and a `ping` subcommand.

## Quickstart

**Prerequisites**

```bash
# Fetch dependencies (one-time, from inside the module directory)
cd quic-link
go mod tidy
```

**1. Generate an identity on each host (one-time)**

Authentication is mutual raw-public-key pinning (ADR-0004): each host holds an
Ed25519 key and the two ends verify each other's *pin* — `base64(SHA-256(public
key))` — during the QUIC handshake. There are no CA files.

```bash
# On BOTH the server and the client host:
quic-link keygen
# -> pin: <base64>      (the key is written to ~/.config/quic-link/key.pem)
```

Note each host's printed pin (call them `<server-pin>` and `<client-pin>`) and
**exchange them out of band** (paste them to each other). Re-running `keygen` is
idempotent — it reprints the existing pin; `keygen --force` rotates the key
(after which peers must re-pair with the new pin). Pairing-ergonomics upgrades
that shrink this exchange are future work.

**2. On the server** (port 443 UDP must be open)

```bash
quic-link serve \
  --listen :443 \
  --service-addr 127.0.0.1:22 \
  --authorized-client <client-pin>
```

`--authorized-client` is repeatable; at least one pin is required (the agent
refuses to start with an empty set).

**3. On the client**

```bash
quic-link connect \
  --server myserver.example.com:443 \
  --local 127.0.0.1:2222 \
  --pin <server-pin>

# In another terminal:
ssh -p 2222 user@127.0.0.1
```

**4. Ping**

```bash
quic-link ping \
  --server myserver.example.com:443 --count 5 \
  --pin <server-pin>
```

A wrong pin on either end fails the handshake and exits with code 4
(authentication failure); the message names the mismatched pin.

## Build and test

```bash
cd quic-link
go build ./...
go test ./...
```

## Architecture

```
cmd/quic-link/        CLI + subcommand wiring
internal/transport/   QUIC Transport abstraction + interface (TODO: TCP/wss fallback)
internal/identity/    Ed25519 keys, pins, and the raw-public-key pinning TLS handshake
internal/tunnel/      stream↔TCP proxy (serve + connect sides)
internal/probe/       ping: handshake timing + RTT (RFC 9002 §5)
```

---

## Cross-platform notes (Linux & macOS)

The binary runs on both Linux and macOS. There is no platform-specific Go code, no cgo dependency, and no OS-specific syscalls beyond `syscall.SIGTERM`, which is available on both platforms. quic-go v0.60.0 handles all per-OS UDP differences (DPLPMTUD Don't-Fragment bit, ECN, and GSO on Linux) internally. The client binds an IPv4 (`udp4`) socket so on-link LAN peers are reachable on macOS (see the Local Network permission note below).

The integration tests bind loopback (`127.0.0.1`) on ephemeral ports (`:0`), so they run without elevated privileges on both OSes.

### Binding UDP port 443

Binding any port below 1024 requires elevated privileges on both Linux and macOS.

- **Non-root testing**: use a high port instead, e.g. `--listen :4443`.
- **Linux production alternative** (avoids running as root):
  ```bash
  sudo setcap 'cap_net_bind_service=+ep' ./quic-link
  ```
  This grants only the capability to bind low-numbered ports, with no other root privileges. There is no equivalent on macOS; use a high port or `sudo` there.

### UDP receive-buffer warning

quic-go may log a warning if it cannot raise the UDP receive buffer to ~7 MB. This is a performance advisory (the tunnel still functions) but raising the limit silences it and maximises throughput under load.

- **Linux**:
  ```bash
  sudo sysctl -w net.core.rmem_max=7340032
  sudo sysctl -w net.core.rmem_default=7340032
  ```
  To persist across reboots, add both lines to `/etc/sysctl.conf`.

- **macOS**:
  ```bash
  sudo sysctl -w kern.ipc.maxsockbuf=7340032
  ```

### macOS Local Network permission (macOS 15 Sequoia and later)

On macOS 15+, an app must be granted **Local Network** access before the OS will
deliver its unicast traffic to LAN addresses (`192.168.x`, `10.x`). Until granted,
packets to the local subnet are **silently dropped** while traffic to the public
internet still flows — so `connect`/`ping` to a LAN server time out with
`timeout: no recent network activity` even though the network is fine.

- Grant your terminal app (Terminal, iTerm, or VS Code) Local Network access under
  **System Settings → Privacy & Security → Local Network**, then re-run. If a
  permission prompt appears on first run, click **Allow**.
- Running the client under `sudo` bypasses the check (root changes the responsible
  process), which is a quick way to confirm this is the cause.
- The client binds an IPv4 socket (`udp4`) rather than a dual-stack `[::]` socket:
  on macOS a dual-stack socket fails to transmit to an on-link IPv4 neighbour.

### `--service-addr` must be a dial target

`serve --service-addr` is the address the server *dials* to reach the upstream
service (sshd), not a bind address. Use `127.0.0.1:22`, not `0.0.0.0:22`
(`0.0.0.0` is a listen/wildcard address and is not a valid dial target).

---

## Configuration file

quic-link reads `~/.config/quic-link/config.toml` by default. A different path
can be specified with the global `--config PATH` flag.

**Precedence** (highest to lowest):
1. Command-line flags
2. Environment variables (`QUIC_LINK_*`)
3. Config file
4. Built-in defaults

The config file uses TOML format with strict unknown-key rejection — any
unrecognised key is a startup error. Changes to the file take effect only after
a restart.

### Client (`connect` / `ping`)

```toml
schema = 1

[servers.myserver]
addr = "myserver.example.com:443"    # host:port of the agent
pin  = "<agent-pin>"                 # from 'quic-link keygen' on the agent

# Optional per-server settings:
# enabled    = true                  # set to false to skip this server
# local_ports = { ssh = 2222, docker = 2375 }  # override local port selection
```

### Agent (`agent` / `serve`)

```toml
schema = 1

[identity]
key_file          = "~/.config/quic-link/key.pem"  # default
warn_key_age_days = 180   # log a rotation reminder after this many days (0 = off)
refuse_old_key    = false # if true, agent refuses to start with an over-age key

[agent]
listen             = ":443"
authorized_clients = ["<client-pin>"]   # repeatable; at least one required

# Optional route overrides:
# [agent.routes]
# ssh    = "tcp://127.0.0.1:22"
# docker = "unix:///var/run/docker.sock"
```

### Logging

```toml
[log]
level  = "info"   # debug | info | warn | error
format = "text"   # text | json
```

All log-level and format settings can also be controlled via `QUIC_LINK_LOG_LEVEL`
and `QUIC_LINK_LOG_FORMAT` environment variables.