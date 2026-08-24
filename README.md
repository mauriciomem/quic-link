# quic-link

quic-link gives you access to application-level protocols and services running on
a remote machine (SSH, HTTP, Docker, Postgres, anything that speaks TCP) over a
single encrypted, mutually-authenticated connection.

No VPN. No root for everyday use. No editing your SSH config, your Docker setup,
or any other application config file: quic-link never touches one.

## Why quic-link

- **One static binary**: the same executable is the client-side **daemon** and the
  server-side **agent**. **One QUIC connection** multiplexes every stream.
- **Authentication is mandatory**: each end holds an Ed25519 key and pins the
  other's public key during the handshake. No CA files to manage, and no
  unauthenticated mode.
- **Only one end has to be reachable.** Either end may dial, so a client that can
  accept nothing can wait for its agent to call in instead. You supply the
  address: quic-link does no address discovery of any kind.
- **Sessions reconnect unattended,** and local ports stay stable across restarts.
- **No mandatory root,** with exactly one opt-in exception, below.

## Install

```bash
curl -fsSL https://github.com/mauriciomem/quic-link/raw/HEAD/scripts/install.sh | sh
```

Set `QLINK_INSTALL_DIR` to install somewhere other than `~/local/bin`, or
`QLINK_VERSION` to pin a tag, including a pre-release (which `latest` skips).

## Quickstart

Three commands, no configuration file, no root.

**1. Generate an identity on each host,** and exchange the two printed pins out of
band.

```bash
quic-link keygen
```

Running it again is idempotent and prints the same pin. `--force` rotates the key,
after which every peer must re-pair.

**2. On the remote host, run the agent:**

```bash
quic-link agent --listen :7443 --authorized-client <client-pin>
```

**3. On your own machine, run the daemon:**

```bash
quic-link daemon --server-add web=HOST:PORT --server-pin web=<agent-pin>
```

That is a working tunnel. From another shell:

```bash
quic-link ssh web
eval $(quic-link docker-env web) && docker ps
```

Neither needs a port number. quic-link picks a stable local port per service and
keeps it across restarts. `quic-link status --json` will always report the ports in
use, and your configuration can pin them if you would rather choose your own.

## Beyond the quickstart

- **Reach a service by hostname**: open it in a browser by name. This is the only
  operation that ever needs root: `sudo quic-link init` writes one system file, and
  `init --undo` removes it again.
- **Carry more than SSH and Docker**: `quic-link agent --route NAME=tcp://host:port`
  adds a target; the client only ever names it, never an address.
- **`quic-link expose`** publishes a new service name on an already-running agent,
  with no restart and no config edit.
- **`quic-link doctor`** reports what is set up on this machine and what is not.
- You can start the daemon at login with a systemd user unit or launchd agent you own.

## Documentation

- [`docs/getting-started.md`](docs/getting-started.md): up and running, in a little
  more depth
- [`docs/architecture.md`](docs/architecture.md): how the tunnel works
- [`docs/cli.md`](docs/cli.md): every verb, its flags, and the exit codes
- [`docs/configuration.md`](docs/configuration.md): the config file and its keys
- [`docs/running-as-a-service.md`](docs/running-as-a-service.md): reference systemd user
  unit and launchd agent — files you copy and own, because quic-link installs none
- [`docs/platform-notes.md`](docs/platform-notes.md): per-platform gotchas and the UDP
  receive buffer note

Each page is kept reasonably current but may drift a little behind the code; the
CLI's own `--help` always has the final word. Interested in building from source?
See [`CONTRIBUTING.md`](CONTRIBUTING.md).
