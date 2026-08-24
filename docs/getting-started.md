# Getting started

*This page is meant to be kept reasonably current, but it might drift a little
behind the code. If something here does not match what you see, the CLI's own
`--help` output is the final word.*

The README's quickstart is the minimal working example. This guide goes a step
further: the same setup shown three different ways. All CLI arguments, a minimal
file, then a file that turns on the features worth having. For exhaustive lists,
see [`docs/cli.md`](cli.md) and [`docs/configuration.md`](configuration.md).

Throughout, a *pin* is what `quic-link keygen` prints on the **other** host. The two
ends never share a key, only pins, and both ends verify. A pin must be base64 of a
32-byte SHA-256; anything else is refused at startup with a message saying so.

## 1. More arguments, still no config file

A daemon can be defined entirely from flags. Nothing is read from disk except your
own key:

```bash
# Client host: two servers, no config file anywhere.
quic-link daemon \
  --server-add web=web.example.com:7443     --server-pin web=<web-agent-pin> \
  --server-add lab=lab.example.com:7443     --server-pin lab=<lab-agent-pin>
```

Both flags are repeatable, and each `--server-add` needs a matching `--server-pin`:
a server cannot be reached without one, since the pin is what proves which key
answered.

One thing to know before mixing the two worlds: **`--server-add` and `--server-pin`
*replace* the servers in your settings file rather than merging with them.** Every
other setting merges normally: for these two options, command-line arguments always
take precedence over the equivalent settings in the configuration file.

The agent side takes flags just as readily. `ssh` and `docker` are always present;
`--route` adds anything else:

```bash
# Agent host: expose sshd, docker, and a Postgres that only listens on loopback.
quic-link agent --listen :7443 \
  --authorized-client <client-pin> \
  --route pg=tcp://127.0.0.1:5432 \
  --route metrics=tcp://127.0.0.1:9090
```

At least one `--authorized-client` is required. There is no unauthenticated mode, in
any configuration.

Now reach that Postgres from the client, with no config and no restart:

```bash
quic-link fwd web pg          # prints: listening 127.0.0.1:<port> -> web:pg
psql -h 127.0.0.1 -p <port>   # or ask for a fixed port: quic-link fwd web pg:5432
```

`fwd` names a *route*, never an address. The far-side host and port are fixed on the
agent, so a route stays a service rather than becoming a port scanner.

**Local ports are allocated, not fixed.** They are derived deterministically, so they
are stable across restarts, but they are not constants you can memorise or copy from
a document. Remember that `quic-link status --json` always reports the ports
actually in use.

`daemon` runs in the foreground and does not daemonise itself. To keep it running
in the background, see [`docs/running-as-a-service.md`](running-as-a-service.md)
for a systemd user unit and a launchd agent you copy and own. Only one daemon may
hold the socket at a time; a second exits 3 and tells you so.

## 2. A minimal configuration file

The file lives at `~/.config/quic-link/config.toml` by default; `--config PATH`
points elsewhere. It is never created or edited for you.

On the client host:

```toml
[servers.web]
addr = "web.example.com:7443"
pin  = "<web-agent-pin>"
```

On the agent host:

```toml
[agent]
listen             = ":7443"
authorized_clients = ["<client-pin>"]
```

That is all of it. Then `quic-link daemon` manages every enabled server in
the file, and `quic-link ssh web`, `quic-link ping web --count 5`, and
`eval $(quic-link docker-env web)` all find their server by name.

Remember that settings resolve **flags > environment > file >
defaults**, so you can override one value for one run without editing anything. And
**unknown keys are rejected at startup**, naming the offending line.

## 3. An extended configuration file

Here is a client file using the features that change what quic-link can do, rather
than every key that exists.

```toml
[servers.web]
addr = "web.example.com:7443"
pin  = "<web-agent-pin>"

# Reverse mode: this machine waits, and the agent connects in.
[servers.homelab]
listen = ":17443"
pin    = "<homelab-agent-pin>"

# Optional: pin the local ports instead of letting quic-link pick them.
[servers.homelab.local_ports]
ssh    = 2222
docker = 2375

[servers.retired]
addr    = "old.example.com:7443"
pin     = "<old-agent-pin>"
enabled = false          # kept by name for status and error messages; not connected
```

And the agent that pairs with `homelab`:

```toml
[agent]
dial               = "workstation.example.com:17443"
authorized_clients = ["<client-pin>"]

# Let a client publish hostnames on this running agent. Off by default.
allow_remote_route_mutation = true

[agent.routes]
pg  = "tcp://127.0.0.1:5432"
app = "tcp://127.0.0.1:3000"
```

The `homelab` server above uses **reverse mode**: it waits instead of calling out,
which is why the agent that pairs with it says `dial`. Section 4 explains why.

**Reaching services by hostname** is the other big one. Run `sudo quic-link init`
once. That is the single operation needing root, it writes exactly one file, and
`quic-link init --undo` removes it. After that, names ending in `.internal` resolve
on this machine and a browser can reach a service directly. Then, against a running agent
that opted in with `allow_remote_route_mutation`:

```bash
quic-link expose homelab 3000 --name app   # publishes a name; no restart, no config edit
quic-link vhosts homelab                   # list names, and where each came from
quic-link vhosts rm app homelab            # withdraw one published at runtime
```

Publishing and withdrawing both need that opt-in; *listing* does not, since reporting
what a name table holds is not changing it. A name from the agent's own config file
cannot be withdrawn remotely at all, because it belongs to whoever runs that agent.

Skipping `init` is fully supported. Everything except reaching a server by name in a
browser works without it.

## 4. Reverse mode

Normally your machine (the daemon) connects out to the remote machine (the agent), so
the agent needs an address you can reach. Reverse mode turns the call around: the
daemon waits, and the agent connects out to it.

### Why you would want that

Connections have a direction, and the two directions are not equally easy.

- **Outbound** means a machine starts the conversation. This works almost anywhere.
- **Inbound** means something on the internet starts a conversation with that machine.
  This very often does not work at all.

A home machine usually sits behind NAT, an arrangement where every device in the house
shares one public address (the address the rest of the internet sees). Because it is
shared, no address arrives at your machine in particular. Many ISPs go further with
carrier grade NAT, sharing one address among many customers, and then there is nothing
you could forward even if you administered the router yourself. An office or campus
network you do not control has the same effect. Reverse mode lets the machine in that
position be the one that calls out.

### The honest limit

Reverse mode **moves** the reachable port, it does not remove it. **One end must still
accept a connection**, and what you gain is choosing which end. quic-link does no
address discovery of any kind: no STUN, no UPnP, no hole punching, no relay, no third
party in the path. You supply the address. So pick the end you can open a port on, and
make that end wait.

### An example

A machine at home holds something you want to reach, behind an ISP you cannot forward a
port on. Your workstation is somewhere you can open one UDP port. So it waits, and the
home machine calls in.

```toml
# On your workstation, which waits.
[servers.homelab]
listen = ":17443"
pin    = "<the home machine's pin>"
```

```toml
# On the home machine, which connects out.
[agent]
dial               = "workstation.example.com:17443"
authorized_clients = ["<the workstation's pin>"]
```

Start the workstation half and it logs `waiting for agent to connect`, with
`listen=[::]:17443`. Until an agent arrives, `quic-link status` reports `listening`.

### Rules worth memorising

Each end picks exactly one direction, and the two ends must **disagree**. On the
client that is `addr` (this machine connects out) or `listen` (this machine waits);
on the agent it is `listen` or `dial`. Setting both is refused rather than guessed
at. A `listen` port below 1024 is refused too, because the daemon deliberately takes
no privilege, so use 1024 or above. Two `listen` servers need different pins, since
an inbound connection is identified by its pin and nothing else. Pins themselves are
unaffected by direction: which identities each end trusts is the same question
whoever places the call.

Whichever end waits needs its UDP port reachable: allow the port through that machine's
firewall, and if it sits behind a router you control, forward that UDP port to it.

Nothing else changes. You still type `quic-link ssh homelab` on the daemon's machine,
the agent still decides which services may be reached, and once the connection is up it
carries streams both ways regardless of who opened it. There is a deeper treatment
in [architecture](architecture.md#reverse-mode).

## Checking it worked

```bash
quic-link doctor                  # what is in place, what is missing, what to do next
quic-link status                  # session state per server, and each one's direction
quic-link status --json           # the same, machine-readable, with the real local ports
quic-link status --routes web     # ask web's agent, live, what it currently serves
quic-link ping web --count 5      # handshake and round-trip time
```

Sessions reconnect on their own after a network drop, so a session that is briefly
down is usually not something to act on. A wrong pin is different: it fails the
handshake and exits 4, naming the mismatched pin.

## Where to go next

- [`docs/cli.md`](cli.md) — every verb, its flags, and the exit codes
- [`docs/configuration.md`](configuration.md) — every config key, including the
  optional `[identity]` and `[log]` blocks
- [`docs/architecture.md`](architecture.md) — how the tunnel works
- [`docs/running-as-a-service.md`](running-as-a-service.md) — start the daemon at login
- [`docs/platform-notes.md`](platform-notes.md) — platform gotchas
