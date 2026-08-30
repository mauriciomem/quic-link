# Reference

This page holds the detail that [`docs/cli.md`](cli.md) and
[`docs/configuration.md`](configuration.md) leave out so they can stay short: every
edge case, every permission requirement, every "what happens if." Read it when an
orientation page's summary is not enough for what you are about to do.

## Verbs in depth

Detail for the verbs whose behavior does not fit in a table cell: the two that
publish and withdraw hostnames on a running agent, and the one that sets up name
resolution on this machine.

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

---

See [`docs/cli.md`](cli.md) for the full verb table and exit codes, and
[`docs/configuration.md`](configuration.md) for the config file and its keys.
