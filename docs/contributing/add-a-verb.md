# Adding a CLI verb

A practical walkthrough of adding a new subcommand, keyed to `version` — the
simplest existing verb — as the reference pattern. Read `cmd/quic-link/version.go`
alongside this page; it is short enough to read in full.

This describes how the codebase is structured today, for anyone reading the
source or building from it. It is not an invitation to open a pull request — see
[`CONTRIBUTING.md`](../../CONTRIBUTING.md) for the project's current stance on
external contributions.

## 1. Create `cmd/quic-link/<verb>.go`

Every verb is one file with a `newXCmd(a *app) *cobra.Command` constructor (a
verb needing no app state, like `version`, takes no argument:
`func newVersionCmd() *cobra.Command`). The constructor builds a `*cobra.Command`
with `Use`, `Short`, `Long`, an `Args` validator, and a `RunE`. Flags are added to
the returned command below the struct literal, not inside it, so their default
values are visible without reading the whole function.

`version`'s `Long` help doubles as its own documentation of the `--json` shape it
prints — see step 5 below.

## 2. Set `Args: wrapArgs(cobra.<Validator>)`

This is not optional, and it is easy to get wrong in a way that produces no
compile error and no obvious test failure. `cmd/quic-link/util.go`'s own doc
comment on `wrapArgs` explains why:

> cobra calls the Args validator from a code path entirely separate from flag
> parsing: `ValidateArgs`'s error propagates straight up to `ExecuteContext`
> unwrapped, so without this wrapper a wrong argument count would fall through
> `exitCodeForError`'s default case and exit 1 instead of the CLI contract's 2.
> Every command that sets an Args validator must wrap it with this helper.

In other words: cobra's own validator errors and this codebase's hand-written
`usageErrorf` errors travel two different paths to the same exit-code mapping
function, and only one of those paths is wired to produce exit 2 by default.
`wrapArgs` closes that gap by re-wrapping the validator's error as a
`usageErrorf` before it leaves the validator. Skip it, and a stray positional
argument to your new verb exits 1 — silently wrong, and easy to miss because the
verb otherwise works.

15 of the 17 commands registered today — 16 top-level plus the nested
`vhosts rm` — already set a validator this way:

| Command | File:line | Validator |
|---|---|---|
| `agent` | `agent.go:63` | `NoArgs` |
| `attach` | `attach.go:24` | `ExactArgs(2)` |
| `connect` | `connect.go:31` | `MaximumNArgs(1)` |
| `daemon` | `daemoncmd.go:120` | `NoArgs` |
| `doctor` | `doctor.go:86` | `NoArgs` |
| `docker-env` | `dockerenv.go:49` | `MaximumNArgs(1)` |
| `expose` | `expose.go:29` | `RangeArgs(1, 2)` |
| `init` | `initcmd.go:56` | `NoArgs` |
| `keygen` | `keygen.go:33` | `NoArgs` |
| `ping` | `ping.go:36` | `MaximumNArgs(1)` |
| `status` | `status.go:57` | `MaximumNArgs(1)` |
| `stdio` | `stdio.go:48` | `ExactArgs(2)` |
| `version` | `version.go:33` | `NoArgs` |
| `vhosts` | `vhosts.go:108` | `MaximumNArgs(1)` |
| `vhosts rm` | `vhosts.go:144` | `RangeArgs(1, 2)` |

`ssh` and `fwd` are the two deliberate exceptions. Both parse their own
positional args (see the "No Args validator" comment in each file) because
their argument shape does not fit a canned cobra validator. Pick whichever
validator matches your verb's actual argument shape. `version` takes none,
so it uses `cobra.NoArgs`.

## 3. Resolving a server name, if your verb takes one

If your verb accepts a `SERVER` argument, resolve it through
`requireKnownServer` (`cmd/quic-link/resolve_server.go:65`), not by indexing
`a.cfg.Servers` directly. `requireKnownServer` asks the running daemon first
and falls back to the settings file. A server defined purely on a command
line to `quic-link daemon` exists only in that process's memory, so a second
command has no file to read it from and must ask the daemon instead.

Six verbs call it today: `dockerenv`, `expose`, `fwd`, `ssh`, `status`, and
`vhosts` (both the listing and its nested `rm`). `ping`, `stdio`, and
`connect` are the three exceptions, each for its own reason.

`ping` is a deliberate exception, not a precedent to copy without reason.
Each `ping` probe opens its own fresh QUIC connection (`ping.go:224-226`), so
it needs a real address and pin up front, something the daemon's status
socket does not expose. `ping.go:47` indexes `a.cfg.Servers` directly on its
happy path, and only reaches `knownServers` inside `pingUnknownServerError`
to word a failure message, never to resolve. If your new verb has the same
structural reason (it opens its own connection rather than asking the daemon
to act on its behalf), following `ping`'s shape is correct. Otherwise, use
`requireKnownServer`.

`stdio` (`stdio.go:67`) is another exception, for a different reason: it
calls `knownServers` directly instead of `requireKnownServer`. `stdio` has a
third resolution path: `--server`/`--pin` flags that bypass config entirely
for a config-free direct dial. Its unknown-server check only runs when
neither flag was given, and each of its three error branches says so
explicitly ("... and --server/--pin were not given"), pointing the caller at
the alternative.

`ssh` has the same flags and handles them the other way. It computes
`flagMode` (`ssh.go:190`) once and skips the check entirely with
`if !flagMode` (`ssh.go:225`), which is why it can still delegate to
`requireKnownServer` for the rest. `stdio` folds the condition into each of
its own messages instead, because `requireKnownServer`'s fixed wording has
no way to append "(and --server/--pin were not given)" to itself. So `stdio`
writes its own switch over `knownServers`'s result rather than delegating to
it.

`connect` is the third exception: it takes `[SERVER]` (`connect.go:23`) and
resolves it through `enabledServers` (`connect.go:74`), the same
`Enabled`-filtering function its own `--help` describes — never
`requireKnownServer` or `knownServers`. It is a deprecated alias for
`daemon --server NAME` and not a pattern to extend.

## 4. Register the command in `root.go`

Add your constructor call to the `root.AddCommand(...)` list in
`cmd/quic-link/root.go`. The list is a plain call with one command per line — no
registry, no init-time side effects. If the verb is plumbing rather than
something a user is meant to type (`stdio` is the current example — see
`docs/cli.md`'s "A note on hidden verbs"), set `Hidden: true` on the command
instead of omitting it from the list; a hidden verb is still registered and
still runs, it just does not appear in `--help`.

Either way, `main.go`'s own doc comment is a maintainer-curated shortlist,
not a table you should assume you're adding to: leave it alone unless your
verb replaces or renames one of the entries already there, in which case
update that line. A non-hidden verb also gets a row in `docs/cli.md`'s
table, in the same commit (step 7); a hidden one does not, by that page's
own "A note on hidden verbs" convention.

## 5. If the verb has a machine-readable `--json` output, freeze it in `--help`

`version` and `vhosts`/`vhosts rm` mark their `--json` shape as `CONTRACT`
directly in the command's own `Long` help text (see `version.go:29-32`,
`vhosts.go:102-104`, and `vhosts.go:140-142` for `vhosts rm`). That is the
convention: the canonical shape for a frozen output lives in exactly one
place, the verb's own `--help`, and `docs/cli.md` points at `--help` rather
than reproducing the shape a second time. Two copies of a schema is two
places for them to drift apart; one copy with everything else pointing at
it cannot drift from itself.

## 6. Add a test file

This package's convention is one `_test.go` file per verb or feature area, not
one giant test file for the whole package. For asserting exit codes specifically,
`cmd/quic-link/cobra_exit_test.go`'s `TestCobraErrorsExitTwo` and
`status_routes_test.go`'s `TestStatusRoutes_ExtraArgWithoutRoutesFlag_Exit2` are
worth reading directly as models — both drive the command end-to-end through the
package's `runVerb`/`exitCode` test helpers (`verb_test.go`) rather than calling
`exitCodeForError` in isolation, because the bug class `wrapArgs` guards against
only shows up when cobra's own validator path is actually exercised.

## 7. Update `docs/cli.md` and `scripts/expected-counts.txt` in the same commit

A non-hidden verb belongs in `docs/cli.md`'s verb table — one row, in the
same commit that adds the verb. A hidden verb is deliberately left out; see
`docs/cli.md`'s "A note on hidden verbs". And adding a test changes how many
results `scripts/test.sh` expects to see reported; forgetting to update
`scripts/expected-counts.txt` in that same commit is the single most common way
to make the suite fail for a reason that looks unrelated to your change. See
[`testing-conventions.md`](testing-conventions.md) for the full mechanics of that
canary — this page only needs you to know it exists and that it moves with your
test file, not why it exists.
