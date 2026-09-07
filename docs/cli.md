# CLI reference

*This page is meant to be kept reasonably current, but it
might drift a little behind the code. If something here does not match what you see,
the CLI's own `--help` output is the final word.*

Run `quic-link <verb> --help` for the current flags. That output comes straight from
the command definitions in the code, so it's authoritative; this table was written
by hand and can lag behind it.

## Verbs

Every verb also accepts two flags from the root command, not listed per row below:
`--config PATH` (use a different config file) and `--log-level LEVEL` (`debug`,
`info`, `warn`, or `error`; default `info`). The table below lists each verb's own
flags — not these two, since they apply everywhere.

| Verb | What it does | Flags |
|---|---|---|
| `keygen` | Generate (or reuse) an Ed25519 identity and print its pin. Run once per host. | `--force` (rotate the key), `--out PATH` |
| `agent` | Run the server-side endpoint: serve routes to an authorized client. | `--listen ADDR` or `--dial ADDR` (mutually exclusive), `--authorized-client PIN`, `--ssh-addr`, `--docker-addr`, `--route NAME=ADDR`, `--key PATH`. See [the reference page](reference.md#agent). |
| `daemon` | Run the client-side session owner in the foreground: connects to the agent(s), or waits for one configured with `listen` to connect in, holds sessions, binds local ports. | `--server NAME`, `--server-add NAME=ADDR`, `--server-pin NAME=PIN`. See [the reference page](reference.md#daemon). |
| `status` | Show the daemon's current session state, including which direction each server uses. | `--json` (machine-readable), `--routes` (also ask SERVER's agent for its live route table) |
| `ping` | Measure handshake time and round-trip time to an agent. | `--count N`, `--key PATH` (identity key), `--server ADDR --pin PIN` (config-free) |
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

`expose`, `vhosts`, and `vhosts rm` publish, list, and withdraw hostnames on a
running agent. Publishing and withdrawing both need the agent's operator to have
turned on `allow_remote_route_mutation`; listing needs no permission. See
[the reference page](reference.md#verbs-in-depth) for the full detail: what
survives a restart (nothing), what happens when a wildcard pattern shadows a
withdrawn name, and the frozen `--json` shapes.

`init` sets this machine up to reach servers by name. Run it with `sudo` to
register the resolver, or without `sudo` to see which of your own account's files
are ready. It is optional and idempotent — see
[the reference page](reference.md#verbs-in-depth) for what each half does and
what running without it costs you.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | ok |
| `1` | something else went wrong; the message on stderr says what |
| `2` | bad usage (bad flags, missing or extra arguments, invalid values), or the daemon's socket path is occupied by something that does not answer like a daemon |
| `3` | the agent could not be reached, or the daemon is not usable (not running, stale schema, another owner already holds the socket, or the requested docker endpoint is not ready) |
| `4` | the pin did not match (authentication failure, either direction), or the agent authenticated you but denied the destination |
| `5` | the agent understood the request and refused it |

`ssh` and `attach` exit with the child ssh process's own status once it actually runs; this
table's codes apply only when quic-link's own logic (dial, auth, refusal) is what failed — see
below for the one case that overrides even the child's status.

If that child is killed by a signal instead of exiting normally — the ordinary result of a
first Ctrl-C, which cancels the context and makes `exec.CommandContext` kill the child — Go
reports the child's `ExitCode()` as `-1` rather than a signal-derived number, and quic-link
passes that value through unchanged. The OS reports `os.Exit(-1)` as exit status `255`, so a
signal-killed `ssh`/`attach` child surfaces as `255`, distinct from the normal-exit status
passthrough described above. Note that `ssh` itself also exits `255` on its own errors
(connection failure, host-key rejection), and the remote command run over `ssh` may also exit
`255` on its own — so `255` does not by itself distinguish a signal-killed child, an ssh that
failed to connect, and a remote command that happened to exit `255`.

Any quic-link process that misses its shutdown grace period (30s), or gets a second termination
signal, is force-exited with code `1` — including `ssh` and `attach`, where this overrides the
child's status described above.

## A note on hidden verbs

A couple of plumbing verbs (used internally by `ssh`, `fwd`, and similar) are
deliberately left out of `--help` because they are not meant to be run by hand and
would only add noise to the command list. If you notice quic-link invoking a verb
you don't recognize in a process list, that's expected; the verbs above are the
supported, documented surface.
