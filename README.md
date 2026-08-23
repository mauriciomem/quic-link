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
`status` command over a local socket. The loopback naming layer is complete: names
resolve, a browser reaches a service by hostname, and `expose` publishes a further
name on a running agent. Job runners are designed but deliberately unscheduled.

## Quickstart

**0. Get the binary.** One command, or download by hand, or build from source.

```bash
curl -fsSL https://github.com/mauriciomem/quic-link/raw/HEAD/scripts/install.sh | sh
```

That detects your platform, downloads the matching release archive, checks it
against the release's own `SHA256SUMS`, and puts a single binary in
`~/local/bin`. It then tells you whether that directory is on your `PATH` and,
if it is not, prints the exact line to add and which file to add it to.

**It uses no `sudo`, writes nothing outside your home directory, edits no shell
profile, and installs no service.** That is deliberate: exactly one quic-link
command ever needs root — `sudo quic-link init`, step 2 below — and an installer
that quietly did that work would remove the one moment you are told what is
changing on your machine. Read it before running it if you would rather:
[`scripts/install.sh`](scripts/install.sh).

Two variables adjust it: `QLINK_INSTALL_DIR` for somewhere other than
`~/local/bin`, and `QLINK_VERSION` to pin a tag (including a pre-release, which
`latest` deliberately skips).

<details>
<summary>Or download by hand</summary>

Releases carry one archive per platform, plus a `SHA256SUMS` file. Pick the one
matching your machine, from the
[releases page](https://github.com/mauriciomem/quic-link/releases):

```bash
tar -xzf quic-link-<version>-<os>-<arch>.tar.gz
cd quic-link-<version>-<os>-<arch>
./quic-link version
```

The archives are checksummed and carry build provenance, so you can confirm both
what you downloaded and where it came from:

```bash
sha256sum -c SHA256SUMS                                   # or: shasum -a 256 -c
gh attestation verify quic-link-*.tar.gz -R mauriciomem/quic-link
```

The second command asks GitHub whether that exact archive was built by this
repository's release workflow, from a specific commit. It needs no keys.

</details>

To build from source instead — Go 1.26.4 or newer:

```bash
go build ./...
```

This produces `quic-link` in the repository root. A plain build reports `dev` for
its version; `make release VERSION=v0.1.0` reproduces what a release contains.

Either way, the rest of this guide assumes the binary is on your `PATH` or that
you are invoking it by full path.

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
# {"schema":2,"identity":{...},"servers":[{"name":"myserver","session":"connected",
#  "transport":"dial","since_ms":1234,"local_ports":{"ssh":50330,"docker":50331},
#  "path":"ipv4-direct"}]}
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
- [`docs/running-as-a-service.md`](docs/running-as-a-service.md): reference systemd user
  unit and launchd agent for starting the daemon at login — files you copy and own,
  because quic-link does not install one
- [`docs/platform-notes.md`](docs/platform-notes.md): the two gotchas above,
  plus the UDP receive buffer note

Each page is kept reasonably current but may drift a little behind the code. Use the
CLI's own `--help` to have always the final word. Interested in contributing or
building from source? See [`CONTRIBUTING.md`](CONTRIBUTING.md).
