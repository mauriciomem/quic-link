# Configuration file

*This page is written for people, not scripts. It is kept reasonably current, but it
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
addr    = "myserver.example.com:443"   # required: the agent's host:port
pin     = "<agent-pin>"                # required: from 'quic-link keygen' on the agent
enabled = true                         # optional, default true

[servers.myserver.local_ports]         # optional: pin the local ports instead of
ssh    = 2222                          # letting quic-link pick them automatically
docker = 2375
```

`enabled = false` keeps the server in the file (so `status` and error messages can
still refer to it by name) without the daemon trying to connect to it. `local_ports`
is optional; when you leave it out, quic-link derives a pair of local ports for you
deterministically, so they're stable across restarts. `quic-link status --json`
always tells you the ports actually in use, so you never have to compute them
yourself.

## Agent block: `[agent]`

```toml
[agent]
listen             = ":443"              # required: UDP address to listen on
authorized_clients = ["<client-pin>"]    # required, non-empty: pins allowed to connect

[agent.routes]                           # optional: add or override named targets
# ssh    = "tcp://127.0.0.1:22"          # built in; override here if sshd is elsewhere
# docker = "unix:///var/run/docker.sock" # built in
pg-app = "tcp://127.0.0.1:5432"          # any additional target you want reachable
```

The agent refuses to start with an empty `authorized_clients` list; there is no
unauthenticated mode. The `ssh` and `docker` routes always exist and can only be
overridden, not removed; `[agent.routes]` is where you add anything beyond those
two. Route names must be short (up to 64 characters), made only of letters,
digits, dots, dashes, and underscores.

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
