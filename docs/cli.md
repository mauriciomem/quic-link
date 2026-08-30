# CLI reference

*This page is meant to be kept reasonably current, but it
might drift a little behind the code. If something here does not match what you see,
the CLI's own `--help` output is the final word.*

Run `quic-link <verb> --help` for the current flags. That output comes straight from
the command definitions in the code, so it's authoritative; this table was written
by hand and can lag behind it.

## Verbs

| Verb | What it does | Common flags |
|---|---|---|
| `keygen` | Generate (or reuse) an Ed25519 identity and print its pin. Run once per host. | `--force` (rotate the key), `--out PATH` |
| `agent` | Run the server-side endpoint: serve routes to an authorized client. | `--listen ADDR` (wait for the client) or `--dial ADDR` (connect out to a waiting client; the two are mutually exclusive), `--authorized-client PIN` (repeatable, required), `--ssh-addr`, `--docker-addr`, `--route NAME=ADDR`, `--key PATH` (identity key; note this is `--out` on `keygen`, not `--key`) |
| `daemon` | Run the client-side session owner in the foreground: connects to the agent(s), or waits for one configured with `listen` to connect in, holds sessions, binds local ports. | `--server NAME` (scope to one server; default is all enabled servers) |
| `status` | Show the daemon's current session state, including which direction each server uses. | `--json` (machine-readable), `--routes` (also ask SERVER's agent for its live route table) |
| `ping` | Measure handshake time and round-trip time to an agent. | `--count N`, `--server ADDR --pin PIN` (config-free) |
| `ssh` | SSH to a server through the tunnel; execs the real `ssh` binary. | `-- ssh-args...`, `--server ADDR --pin PIN` (config-free) |
| `docker-env` | Print an `export DOCKER_HOST=...` line for a connected server. | none |
| `fwd` | Ad-hoc local port forward to any route-table target, not just `ssh`/`docker`. | `[SERVER] TARGET[:LOCAL_PORT]` |
| `attach` | Shorthand for attaching to a tmux session over `ssh`. | `SERVER SESSION` |
| `expose` | Ask a server's agent to publish one of its local ports under a hostname, for as long as that agent runs. | `[SERVER] PORT --name NAME` (`--name` required) |
| `vhosts` | List the hostnames a server currently publishes, and where each came from. | `[SERVER]`, `--json` |
| `vhosts rm` | Withdraw a hostname that was published on a running agent. | `NAME [SERVER]`, `--json` |
| `doctor` | Report what is set up on this machine, and what is not. Changes nothing. | `--json` |
| `init` | Set this machine up to reach servers by name. | `--yes` (skip confirmation), `--undo` (remove what a previous run installed) |
| `version` | Print the CLI's build version and the wire protocol version. | `--json` |

`connect` still works but is a deprecated alias for `daemon --server NAME`; use
`daemon` in anything new.

`expose` publishes a name only for as long as that agent process runs, and writes
nothing to disk on either side; a change accepted under an operator's permission
should not outlive the process that accepted it. It needs the agent to have opted
into `allow_remote_route_mutation`. `SERVER` can be left out of `expose`, `vhosts`,
and `vhosts rm` when exactly one server is known — asked of the running daemon
first, then the settings file; neither source filters out a disabled server, so
"known" is the right word here, not "enabled".

`vhosts` lists what a server's agent is publishing right now, not what a config
file says, and reports each name's provenance, since only a runtime-published name
can later be withdrawn; reading needs no permission from the agent's operator.
`vhosts rm` can only withdraw a runtime-published name; a name from the agent's
own configuration is refused, and the refusal says which kind is in the way. Like
`expose`, it needs `allow_remote_route_mutation` on. If a wildcard pattern in the
agent's configuration also covers the withdrawn name, that name keeps resolving
afterward at whatever address the pattern points to; both are reported when it
happens. Both verbs' `--json` output is a frozen shape (marked `CONTRACT` in
`--help`); see `quic-link vhosts --help` and `quic-link vhosts rm --help` for the
exact fields.

`init` run with `sudo` writes exactly one system file, the resolver
registration, which is the only part needing a password. Run without `sudo` it
installs nothing and instead reports which of your own account's files are in
place — an identity key and a settings file — and what to do about each missing
one: a command (`quic-link keygen`) for the key, but for settings, only a path
to write by hand, since composing your own settings file is not something a
command can do for you. It is idempotent and reports what it will do before
doing anything. Skipping `init` entirely is supported: everything except
reaching a server by name in a browser works without it. Registering the
resolver is `init`'s whole job; the daemon still does the actual work of
binding the naming ports and answering lookups once it is running.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | ok |
| `1` | something else went wrong; the message on stderr says what |
| `2` | bad usage (bad flags, missing or extra arguments, invalid values), or the daemon's socket path is occupied by something that does not answer like a daemon |
| `3` | could not reach the agent, or the daemon is not running |
| `4` | the pin did not match (authentication failure, either direction) |
| `5` | the agent understood the request and refused it |

## A note on hidden verbs

A couple of plumbing verbs (used internally by `ssh`, `fwd`, and similar) are
deliberately left out of `--help` because they are not meant to be run by hand and
would only add noise to the command list. If you notice quic-link invoking a verb
you don't recognize in a process list, that's expected; the verbs above are the
supported, documented surface.
