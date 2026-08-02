# quic-link

quic-link gets you SSH and Docker access to a remote machine over one encrypted,
mutually-authenticated connection. No VPN, no root on either end, and no editing
your SSH config or Docker setup: point normal `ssh` and `docker` commands at a
local port quic-link holds open for you.

Under the hood it's one binary that runs as a client-side **daemon** and a
server-side **agent**, multiplexing traffic over a single QUIC connection. Each
end holds an Ed25519 key and pins the other's public key during the handshake;
there are no CA files to manage.

**Status:** core tunnel is complete (framed protocol, SSH + Docker routes, pinned
identity, TOML config). A client-side daemon manages sessions and exposes a
`status` command over a local socket; a loopback naming layer and job runners
are in progress.

## Quickstart

**0. Build.** There's no packaged release yet, so this is the only way to get the
binary:

```bash
go build ./...
```

This produces `quic-link` in the repository root; the rest of this guide assumes
it's on your `PATH` or you're invoking it by full path.

**1. Generate an identity on each host (one-time).** Authentication is mutual
raw-public-key pinning: each host holds a key, and the two ends verify
each other's *pin* during the handshake.

```bash
quic-link keygen
# -> pin: <base64>      (key written to ~/.config/quic-link/key.pem)
```

Note each host's pin and **exchange them out of band**. `keygen` is idempotent
(running it again just reprints the existing pin); `keygen --force` rotates the
key, and peers must re-pair with the new pin.

**2. On the agent host**:

```bash
quic-link agent --listen :4433 --authorized-client <client-pin>
```

`--authorized-client` is repeatable; at least one pin is required. The built-in
`ssh` route defaults to `tcp://127.0.0.1:22` (`--ssh-addr` to override);
`--docker-addr` overrides the Docker socket; `--route NAME=ADDR` adds any
further target.

> Binding well-known ports needs elevated privileges on Linux and macOS. See
> [Binding well-known UDP ports](docs/platform-notes.md#binding-well-known-udp-ports) for a
> high-port workaround or the Linux capability grant.

**3. On the client, describe the server in a config file.** Write
`~/.config/quic-link/config.toml` (see [Configuration](docs/configuration.md))
naming the agent's address and pin:

```toml
[servers.myserver]
addr = "myserver.example.com:4433"
pin  = "<agent-pin>"
```

**4. Run the daemon:**

```bash
quic-link daemon --server myserver
```

The daemon dials the agent and logs `connected to server` (a structured log
line on stderr, not something printed to stdout), then holds two local TCP
ports open for the life of the session: one for SSH, one for Docker. Find them
with `status`:

```bash
quic-link status --json
# {"schema":1,...,"servers":[{"name":"myserver","session":"connected",
#  "local_ports":{"ssh":50330,"docker":50331},...}]}
```

Use them directly, or reach for the porcelain verbs instead:

```bash
ssh -p 50330 user@127.0.0.1
docker -H tcp://127.0.0.1:50331 ps
```

Or:

```bash
quic-link ssh myserver
eval $(quic-link docker-env myserver) && docker ps
```

Only one `quic-link daemon` owns the local socket at a time.

> On macOS 15 and later, a LAN connection can time out until the terminal app is
> granted Local Network access. See
> [macOS Local Network permission](docs/platform-notes.md#macos-local-network-permission-macos-15-sequoia-and-later)
> if `daemon`/`ping` hangs with `timeout: no recent network activity`.

**5. Ping:**

```bash
quic-link ping myserver --count 5
```

`ping` reads the server's address and pin from the config file. A wrong pin on
either end fails the handshake and exits with code 4; the message names the
mismatched pin.

## Documentation

- [`docs/architecture.md`](docs/architecture.md): how the tunnel works
- [`docs/cli.md`](docs/cli.md): every verb, its flags, and the exit codes
- [`docs/configuration.md`](docs/configuration.md): the config file and its keys
- [`docs/platform-notes.md`](docs/platform-notes.md): the two gotchas above,
  plus the UDP receive buffer note

Each page is kept reasonably current but may drift a little behind the code. Use the
CLI's own `--help` to have always the final word. Interested in contributing or
building from source? See [`CONTRIBUTING.md`](CONTRIBUTING.md).
