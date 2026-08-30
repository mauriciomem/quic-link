# Reference

This page holds the detail that [`docs/cli.md`](cli.md) and
[`docs/configuration.md`](configuration.md) leave out so they can stay short: every
edge case, every permission requirement, every "what happens if." Read it when an
orientation page's summary is not enough for what you are about to do.

## Verbs in depth

Detail for the verbs whose behavior does not fit in a table cell: the two that
run the tunnel itself, the two that publish and withdraw hostnames on a running
agent, and the one that sets up name resolution on this machine.

### `agent`

- **`--listen` and `--dial` are mutually exclusive.** `--listen ADDR` waits for
  a client to connect in. `--dial ADDR` connects out to a client that is
  waiting. Setting both is a usage error.
- **`--authorized-client PIN` is repeatable and at least one is required.**
  The agent refuses to start with none. It never accepts unauthenticated
  connections.
- **`--ssh-addr` and `--docker-addr` are shorthand for `--route ssh=ADDR` and
  `--route docker=ADDR`.** Giving both the shorthand and the equivalent
  `--route` for the same name in one invocation is a usage error, since a
  silent last-wins precedence between two flags that mean the same thing
  would be a trap with no way to see it coming.
- **`--key PATH` defaults to `~/.config/quic-link/key.pem`.** This is the
  same default `keygen` uses, but under a different flag name: `agent` reads
  the key with `--key`, while `keygen` writes it with `--out`. Passing `--key`
  to `keygen` or `--out` to `agent` is a silent no-op, not an error. Worth
  remembering before assuming a flag typo is the reason a key did not move.

### `daemon`

- **No flag manages every enabled server**; `--server NAME` scopes the
  daemon to one.
- **`--server-add NAME=ADDR` is repeatable and replaces the servers in your
  settings file** for this run. It does not merge with them: naming one
  server means only that server, not your whole configured fleet plus it.
- **`--server-pin NAME=PIN` is repeatable and must pair with `--server-add`.**
  Each `--server-add` needs a matching `--server-pin` for the same name, and
  vice versa; the daemon refuses to start otherwise, since a server without a
  pin cannot be reached and a pin without a server names nothing.

### `expose`

- **Lives only as long as the agent process runs.** Nothing is written to disk on
  either side. This is deliberate: a change accepted under an operator's permission
  should not outlive the process that accepted it.
- **Requires `allow_remote_route_mutation`.** The agent's own configuration has to
  turn this on before `expose` is accepted; there is no other way to grant it.
- **`SERVER` can be omitted** when exactly one server is known. "Known" means asked
  of the running daemon first, then the settings file if no daemon answers. Neither
  source filters out a disabled server — that is why this page says "known," not
  "enabled."

### `vhosts`

- **Reports what the agent is publishing right now**, not what its config file
  says.
- **Names each entry's provenance** — where it came from — because only a
  runtime-published name can later be withdrawn.
- **Needs no permission to read.** Listing a name table is not the same as
  changing it, so nothing has to be turned on for this to work.
- `SERVER` can be omitted under the same known-server rule as `expose`.

### `vhosts rm`

- **Withdraws only a runtime-published name.** A name from the agent's own
  configuration belongs to whoever runs that agent; `vhosts rm` refuses to remove
  it and says which kind was in the way.
- **Requires `allow_remote_route_mutation`**, the same as `expose`.
- **Wildcard shadowing.** If a wildcard pattern in the agent's own configuration
  also covers the name you just withdrew, that name keeps resolving afterward, at
  whatever address the pattern points to. Both the pattern and its address are
  reported when this happens.
- `SERVER` can be omitted under the same known-server rule as `expose`.

Both `vhosts` and `vhosts rm` freeze their `--json` shape (marked `CONTRACT` in
`--help`). Run `quic-link vhosts --help` or `quic-link vhosts rm --help` for the
exact fields.

### `init`

`init` splits its work by privilege. Each run does exactly one half, and tells you
what to do for the other.

- **Run with `sudo`:** writes exactly one system file, the resolver registration.
  That is the only part of setup that needs a password.
- **Run without `sudo`:** installs nothing. It reports which of your own account's
  files are in place — an identity key and a settings file — and what to do about
  whichever is missing: a command (`quic-link keygen`) for the key, and a path to
  write by hand for the settings file, since composing your own settings is not
  something a command can do for you.

`init` is idempotent. It reports what it will do before doing anything, and
running it again once everything is already in place changes nothing.

Skipping `init` entirely is supported. Everything works without it except
reaching a server by name in a browser. Registering the resolver is `init`'s whole
job — the daemon still does the real work, binding the naming ports and answering
lookups, once it is running.

## Configuration keys in depth

### `[agent.vhosts]` in depth

Full detail on how a vhost key is built, matched, and counted.

**Composing the key.** A key is the label the service is published under, the
server name (the same one you pass to `daemon --server`, `ssh`, and friends),
and the naming suffix (`internal` by default; see the
[`[names]`](configuration.md#optional-names) section).

**The label is the client's word, not the agent's.** The middle label is the
name the *client* knows this server by. The agent has no knowledge of it, so
this key has to be written to match what the other machine calls it. A key
that is only the label (`app` instead of `app.myserver.internal`) loads
without error but never matches a real request, because nothing ever asks for
the host literally named `app`.

**Patterns and precedence.** A key may also be a pattern: a first label of
`*` stands in for whatever comes before it, so `"*.myserver.internal"`
matches any hostname ending in `.myserver.internal` (one label or several)
that has no more specific exact entry. Precedence works like this:

- An exact key is tried before any pattern.
- Among patterns, the longest matching suffix wins. `app.myserver.internal`
  (exact) beats `*.myserver.internal`, which in turn beats a shorter pattern
  further out.
- Pattern entries count toward the same limit as exact ones.

**The shared 128-name limit.** This table shares its entries and its limit
with anything published at runtime over the control plane (see
[`allow_remote_route_mutation`](#allow_remote_route_mutation) and
`quic-link expose` in
[getting started](getting-started.md#3-an-extended-configuration-file)). The
two kinds of entry count against one limit together: at most 128 published
names total, config-file and runtime-published combined, exact and pattern
together. A config file that exceeds that on its own is rejected at startup,
naming the count and the limit. It is a startup error, not a silent
truncation.

**What can be withdrawn.** A name published here, in the file, can never be
withdrawn remotely. Only a name published at runtime over the control plane
can be, and only by an authorized client, never one from the file.
`quic-link vhosts` is a separate CLI verb for listing published names at
runtime; it fetches the live list straight from the agent, so it includes
names from this table alongside anything published at runtime, each reported
with its provenance so the two are never confused.

### `allow_remote_route_mutation`

It lives directly under `[agent]`, alongside `listen` (or `dial`) and
`authorized_clients`. It is not a separate table, whichever mode you chose.

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

It is deliberately settable only here, in the file, never by a flag, never by
an environment variable. Anything that prepares a process environment (a
service unit, a container definition, a wrapper script) could otherwise flip
it, which is a far wider and less reviewable surface than a file someone
edited on purpose. Only the agent role reads it, so a config file shared
between both roles carries it harmlessly on the client side.

Because it lives in the file, it survives independently of how you start the
agent. A `~/.config/quic-link/config.toml` left over from an earlier setup
still applies its `allow_remote_route_mutation = true` even when you start
`quic-link agent` with explicit flags for everything else. A flag only
overrides a setting it names, and this one has no flag to override it. On a
shared or long-lived box, that means it can be on without anyone having just
passed it.

---

See [`docs/cli.md`](cli.md) for the full verb table and exit codes, and
[`docs/configuration.md`](configuration.md) for the config file and its keys.
