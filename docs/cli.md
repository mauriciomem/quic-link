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
| `agent` | Run the server-side endpoint: accept connections, serve routes. | `--listen ADDR`, `--authorized-client PIN` (repeatable, required), `--ssh-addr`, `--docker-addr`, `--route NAME=ADDR` |
| `daemon` | Run the client-side session owner in the foreground: dials the agent(s), holds sessions, binds local ports. | `--server NAME` (scope to one server; default is all enabled servers) |
| `status` | Show the daemon's current session state. | `--json` (machine-readable) |
| `ping` | Measure handshake time and round-trip time to an agent. | `--count N`, `--server ADDR --pin PIN` (config-free) |
| `ssh` | SSH to a server through the tunnel; execs the real `ssh` binary. | `-- ssh-args...`, `--server ADDR --pin PIN` (config-free) |
| `docker-env` | Print an `export DOCKER_HOST=...` line for a connected server. | none |
| `fwd` | Ad-hoc local port forward to any route-table target, not just `ssh`/`docker`. | `SERVER TARGET[:LOCAL_PORT]` |
| `attach` | Shorthand for attaching to a tmux session over `ssh`. | `SERVER SESSION` |
| `version` | Print the CLI's build version and the wire protocol version. | `--json` |

`connect` still works but is a deprecated alias for `daemon --server NAME`; use
`daemon` in anything new.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | ok |
| `1` | something else went wrong; the message on stderr says what |
| `2` | bad usage (bad flags, missing arguments, invalid values) |
| `3` | could not reach the agent, or the daemon is not running |
| `4` | the pin did not match (authentication failure, either direction) |
| `5` | the agent understood the request and refused it |

## A note on hidden verbs

A couple of plumbing verbs (used internally by `ssh`, `fwd`, and similar) are
deliberately left out of `--help` because they are not meant to be run by hand and
would only add noise to the command list. If you notice quic-link invoking a verb
you don't recognize in a process list, that's expected; the verbs above are the
supported, documented surface.
