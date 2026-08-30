# Configuration file

*This page is meant to be kept reasonably current, but it
might drift a little behind the code. If something here does not match what you see,
the CLI's own `--help` output is the final word.*

## Precedence

Settings are resolved in this order, highest priority first: command-line flags,
then `QUIC_LINK_*` environment variables, then the config file, then built-in
defaults. A flag always wins over an environment variable, which always wins over
whatever the file says.

## Where the file lives

By default quic-link reads `~/.config/quic-link/config.toml`. Pass `--config PATH`
to use a different file. If the file doesn't exist, quic-link falls back to flags
and defaults; it never creates or edits the file for you.

Unknown keys and unknown tables are a startup error naming the offending key, so a
typo is caught immediately rather than silently ignored. Changing the file takes
effect on the next restart of `agent` or `daemon`; there is no live reload yet.

One file can describe both roles at once. If it has a `[servers.*]` block, the
client side (daemon) is available; if it has an `[agent]` block, the agent side is
available. `quic-link agent` and `quic-link daemon` each look only at the section
that matches their own role.

## The `schema` key

```toml
schema = 1
```

This is optional and defaults to `1`, the only schema that exists today. You don't
need to write it, and there's nothing to configure about it yet; it exists so a
future version of quic-link can tell an old config file apart from a new one.

## Client block: `[servers.<name>]`

One block per agent you want to talk to. `<name>` is whatever you want to call it;
it's what you pass to `daemon --server`, `ssh`, `ping`, and friends.

```toml
[servers.myserver]
addr    = "myserver.example.com:443"   # the agent's host:port, when this machine connects out
pin     = "<agent-pin>"                # required: from 'quic-link keygen' on the agent
enabled = true                         # optional, default true

[servers.myserver.local_ports]         # optional: pin the local ports instead of
ssh    = 2222                          # letting quic-link pick them automatically
docker = 2375
```

Exactly one of `addr` and `listen` is required, and they are mutually exclusive.
`addr` means this machine connects to the agent, which is the usual arrangement.
`listen` means the opposite: this machine waits on that address and the agent
connects to it, for when the agent has no address you can reach. Reverse mode is
described in [architecture](architecture.md#reverse-mode); the two ends must
disagree about direction, so an agent talking to a `listen` server here needs
`dial` set in its own config.

```toml
[servers.homelab]
listen = ":17443"                      # wait here instead; the agent connects to us
pin    = "<agent-pin>"
```

Two servers that both use `listen` must have different pins. An incoming connection
is identified by its pin and nothing else, so two waiting servers sharing one could
not be told apart; quic-link refuses that config rather than guessing. Servers that
use `addr` may share a pin freely, since their addresses tell them apart.

A `listen` port below 1024 needs privileges the daemon deliberately does not take.
Pick 1024 or above; see [platform notes](platform-notes.md).

`enabled = false` keeps the server in the file (so `status` and error messages can
still refer to it by name) without the daemon connecting to it or accepting a
connection from it. `local_ports`
is optional; when you leave it out, quic-link derives a pair of local ports for you
deterministically, so they're stable across restarts. `quic-link status --json`
always tells you the ports actually in use, so you never have to compute them
yourself.

## Agent block: `[agent]`

```toml
[agent]
listen             = ":443"              # UDP address to wait on
authorized_clients = ["<client-pin>"]    # required, non-empty: pins allowed to connect

[agent.routes]                           # optional: add or override named targets
# ssh    = "tcp://127.0.0.1:22"          # built in; override here if sshd is elsewhere
# docker = "unix:///var/run/docker.sock" # built in
pg-app = "tcp://127.0.0.1:5432"          # any additional target you want reachable
```

Exactly one of `listen` and `dial` is required, and they are mutually exclusive.
`listen` waits for the client to connect, which is the usual arrangement. `dial`
connects out to a client that is waiting, and pairs with a `listen` server on the
other end:

```toml
[agent]
dial               = "workstation.example.com:17443"
authorized_clients = ["<client-pin>"]
```

The pins the agent accepts are the same either way: the direction of the connection
changes nothing about which identities it trusts.

The agent refuses to start with an empty `authorized_clients` list; there is no
unauthenticated mode. The `ssh` and `docker` routes always exist and can only be
overridden, not removed; `[agent.routes]` is where you add anything beyond those
two. Route names must be short (up to 64 characters), made only of letters,
digits, dots, dashes, and underscores.

```toml
[agent.vhosts]                              # optional: publish services under hostnames
"app.myserver.internal" = "tcp://127.0.0.1:3000"   # reachable as app.myserver.internal
```

`[agent.vhosts]` maps a full hostname — not a bare label — to a target address,
which is how a client that routes by name — a browser, say — reaches a service
directly instead of naming a route. Lookup matches the whole hostname a client
asks for, so a key here has to already be the name a client will actually
request: the label the service is published under, then the server name (the
one used with `daemon --server`, `ssh`, and friends), then the naming suffix
(`internal` by default, see `[names]` below). A key that is only the label —
`app` instead of `app.myserver.internal` — loads without error but never
matches a real request, because nothing ever asks for the host literally named
`app`.

A key may also be a pattern: a first label of `*` stands for any single label
in that position, so `"*.myserver.internal"` matches any hostname ending in
`.myserver.internal` that has no more specific exact entry. An exact key is
tried before any pattern, and among patterns the longest matching suffix wins,
so `app.myserver.internal` (exact) takes precedence over `*.myserver.internal`,
which in turn beats a shorter pattern further out. Pattern entries count
toward the same limit as exact ones.

The table shares its entries and its limit with anything published at runtime
over the control plane (see `allow_remote_route_mutation` below and
`quic-link expose` in
[getting started](getting-started.md#3-an-extended-configuration-file)), and
the two kinds of entry count against one limit together: at most 128 published
names total, config-file and runtime-published combined, exact and pattern
together. A config file that exceeds that on its own is rejected at startup,
naming the count and the limit; it is a startup error, not a silent
truncation. A name published here, in the file, can never be withdrawn
remotely — only a name published at runtime over the control plane can be,
and only by an authorized client, never one from the file. `quic-link vhosts`
is a separate CLI verb for listing published names at runtime; it fetches the
live list straight from the agent, so it includes names from this table
alongside anything published at runtime, each reported with its provenance so
the two are never confused.

```toml
[agent]
allow_remote_route_mutation = true          # off by default
```

Off by default. Turning it on lets any of the agent's already-authorized
clients publish a new hostname at runtime — with `quic-link expose`, no config
edit, no restart — and withdraw one later. This makes every authorized client
of that agent mutually trusting: withdrawal checks a name's *provenance* (was
it published over the control plane at all?), not *which* client published it,
so any authorized client can withdraw a name a different authorized client
published. Any authorized client can also exhaust the shared 128-name table on
its own. Publishing an exact name is also not checked against an
operator-configured pattern that would otherwise have covered it, so an
authorized client can publish an exact name that shadows a pattern from this
file and take over the traffic that pattern was serving. This is a documented
property of an opt-in you turned on, not a disclosed defect — the agent still
refuses to start with no authorized clients.

It is deliberately settable only here, in the file — never by a flag, never by
an environment variable. Anything that prepares a process environment (a
service unit, a container definition, a wrapper script) could otherwise flip
it, which is a far wider and less reviewable surface than a file someone
edited on purpose. Only the agent role reads it, so a config file shared
between both roles carries it harmlessly on the client side.

Because it lives in the file, it survives independently of how you start the
agent. A `~/.config/quic-link/config.toml` left over from an earlier setup
still applies its `allow_remote_route_mutation = true` even when you start
`quic-link agent` with explicit flags for everything else — a flag only
overrides a setting it names, and this one has no flag to override it. On a
shared or long-lived box, that means it can be on without anyone having just
passed it.

## Optional: `[identity]`

```toml
[identity]
key_file          = "~/.config/quic-link/key.pem"   # override the default key location
warn_key_age_days = 180                             # optional, default 180; 0 disables
refuse_old_key    = false                            # optional, default false
```

Most setups don't need this section; `quic-link keygen`'s default path already
matches the default `key_file`. `warn_key_age_days` controls when `agent` and
`daemon` print a startup warning that the local key is getting old; set
`refuse_old_key = true` to make an over-age key a hard startup failure instead of
just a warning.

## Optional: `[log]`

```toml
[log]
level  = "info"   # debug | info | warn | error   (env: QUIC_LINK_LOG_LEVEL)
format = "text"   # text | json                    (env: QUIC_LINK_LOG_FORMAT)
```

Logs go to stderr in either format; this only changes their verbosity and shape,
never where they're written.

## Optional: `[names]`

```toml
[names]
suffix         = "internal"   # optional, default "internal"       (env: QUIC_LINK_NAMES_SUFFIX)
dns_port       = 15353        # optional, default 15353            (env: QUIC_LINK_NAMES_DNS_PORT)
http_port      = 18080        # optional, default 18080            (env: QUIC_LINK_NAMES_HTTP_PORT)
https_port     = 18443        # optional, default 18443            (env: QUIC_LINK_NAMES_HTTPS_PORT)
suffix_is_mine = false        # optional, default false            (env: QUIC_LINK_NAMES_SUFFIX_IS_MINE)
```

This whole table is optional; every field has a default, and leaving it out
entirely is not an error. It controls the naming layer that `quic-link init`
(see [getting started](getting-started.md#3-an-extended-configuration-file))
turns on for the client role, letting names ending in the suffix resolve on
this machine and reach a service directly. `suffix` is reserved for private
use by default (`internal`), so quic-link can register it with the system
resolver without taking a real domain away from anybody. Setting `suffix` to
anything else — a domain you actually control — also requires setting
`suffix_is_mine = true`: it exists so that pointing your machine's resolver at
a real domain is a deliberate act, not a typo left over from testing. The
three ports each need to be distinct and above 1023 — the same floor a
`listen` address is held to elsewhere in this file, though `[names]` is the
one place that floor is checked while the config file is being read, rather
than later when something tries to bind.

