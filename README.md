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

**1. Generate a throwaway PKI (one-time)**

```bash
# CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=quic-link-ca"

# Server cert. Replace 1.2.3.4 / myserver.example.com with your actual values
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -subj "/CN=myserver.example.com"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:myserver.example.com,IP:1.2.3.4")

# Client cert
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr -subj "/CN=client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365
```

**2. On the server** (port 443 UDP must be open)

```bash
quic-link serve \
  --listen :443 \
  --service-addr 127.0.0.1:22 \
  --cert server.crt --key server.key \
  --client-ca ca.crt
```

**3. On the client**

```bash
quic-link connect \
  --server myserver.example.com:443 \
  --local 127.0.0.1:2222 \
  --cert client.crt --key client.key \
  --server-ca ca.crt

# In another terminal:
ssh -p 2222 user@127.0.0.1
```

**4. Ping**

```bash
quic-link ping \
  --server myserver.example.com:443 --count 5 \
  --cert client.crt --key client.key --server-ca ca.crt
```

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
internal/tunnel/      stream↔TCP proxy (serve + connect sides)
internal/probe/       ping: handshake timing + RTT (RFC 9002 §5)
```

---

## Cross-platform notes (Linux & macOS)

The binary runs unchanged on both Linux and macOS. There is no platform-specific Go code, no cgo dependency, and no OS-specific syscalls beyond `syscall.SIGTERM`, which is available on both platforms. quic-go v0.60.0 handles all per-OS UDP differences (DPLPMTUD Don't-Fragment bit, ECN, and GSO on Linux) internally.
No action is required in our code.

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