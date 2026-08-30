# Adding a config key

A practical walkthrough of adding a new configuration key, keyed to `Log.Level`
as the reference pattern — the simplest existing key: a plain string with no
pointer indirection and no cross-field validation. Read
`internal/config/config.go` alongside this page.

This describes how the codebase is structured today. It is not an invitation to
open a pull request — see [`CONTRIBUTING.md`](../../CONTRIBUTING.md) for the
project's current stance on external contributions.

## 1. Add the field to its struct

Every config field carries an explicit `toml:"..."` tag — `Config`
(`config.go:36-43`) holds `Schema`, `Identity`, `Servers`, `Agent`, `Names`,
`Log`, each tagged to its TOML key. `Log.Level` (`toml:"level"`) lives in the
`Log` struct, a plain value type, because logging settings apply unconditionally
regardless of role — there is no state in which "no log settings" is a
meaningful, distinguishable configuration.

Contrast that with `Agent` and `Names`, which are `*Agent` and `*Names` —
pointers. A pointer is required when the table's very absence is meaningful and
must be distinguishable from an empty one: `Config.Agent == nil` means "this
config never mentions `[agent]` at all," which the agent-role validation path
needs to tell apart from `[agent]` written empty. The same reasoning shows up at
field level: `Server.Enabled *bool` (`config.go:59`) carries the comment
`// nil ≡ true (pointer detects unset)` — a pointer exists specifically so
"the operator never set this" and "the operator explicitly set it to false" are
two different states, not one collapsed into the other by a zero value. If your
new key's absence and its zero value mean the same thing, a plain value is
correct, as it is for `Log.Level`. If they do not, use a pointer and say why in
the field's own doc comment — see `Agent.AllowRemoteRouteMutation`'s comment
(`config.go:72-86`) for the level of detail expected: it explains not just what
the field does, but why it is settable only in a file (step 6 below).

## 2. Add a default, if the key needs one

`Log.Level` defaults to `"info"`, set in `Defaults()` (`config.go:125-138`).
Not every key needs an entry here — a key whose absence is itself meaningful
(anything behind a pointer, most of `[names]`) is left unset in `Defaults()` and
resolved elsewhere. When a default does exist, it is worth naming as a constant
next to a comment explaining the choice, the way `internal/config/naming.go:10-24`
does for the naming layer's ports and suffix: `DefaultDNSPort = 15353` because
5355 is taken by a stock systemd-resolved (LLMNR) and 5354 is separately
registered; `DefaultSuffix = "internal"` because it is in the IANA special-use
registry and can never collide with a real top-level domain. A default that
carries its own reasoning next to it means the next person who wants to change
it can tell whether the value was arbitrary or load-bearing.

## 3. Add validation, if TOML's own type-checking is not enough

TOML's decoder already rejects a value of the wrong type. Add code to `Validate`
(`config.go:421` onward) only when a key needs a rule TOML cannot express by
itself — a numeric range, a cross-field constraint, a length bound. `Log.Level`
needs none of that: any string decodes, and an unrecognized level is a `slog`
concern at startup, not a config-load concern, so there is nothing to add here for
this particular key.

Two existing checks are worth reading as models for keys that do need
validation. `agent.vhosts`'s length is checked against `router.MaxVhosts`
(`config.go:654`) at load time rather than letting the vhost table truncate
silently later — validation belongs at the point the operator can still fix the
file, not at the point the limit is discovered by a caller. And `[names]`' ports
are checked against `lowestUnprivilegedPort` (`internal/config/naming.go:27-31,125`):
a port below it is refused when the file is read, rather than surfacing as an
opaque permission error the first time the process tries to bind.

## 4. Decide whether the key needs an environment-variable override

Scalar keys often get a `QUIC_LINK_*` override; table-typed values
(`servers.*`, `authorized_clients`, `routes`, `local_ports`, `vhosts`) do not —
those must come from the file or flags. If your key needs one, add a case to the
`switch` in `applyEnvVar` (`config.go:308` onward, e.g. `QUIC_LINK_LOG_LEVEL` at
`:346-347`). Each case parses and validates its own value and lazily allocates
the owning struct if it is a pointer (see the `QUIC_LINK_AGENT_DIAL` case
allocating `cfg.Agent` right before setting the field, `config.go:340-344`). The
`default` case deliberately returns `false, nil` — recognized as "not one of
ours" rather than silently accepted — so a misspelled variable name is reported
as unrecognized (`mergeEnv` logs a warning listing every unrecognized
`QUIC_LINK_*` variable) instead of looking like it took effect.

If you are removing a key rather than adding one, do not simply stop reading it.
`removedKeyError` (`config.go:730`) is how a retired key like the old
`[ports]` table or `names.block` produces a real, actionable error naming what
replaced it, rather than either silently ignoring the value or reporting it as
merely unknown. A key that once shipped and worked deserves better than looking
like a typo when it stops.

## 5. Document the key in `docs/configuration.md` — in the same commit

This step is not optional, and skipping it is not a small omission: three keys
(`[names]`, `agent.vhosts`, `allow_remote_route_mutation`) once shipped, worked,
and went completely undocumented for a period before that gap was found and
closed. `docs/configuration.md` is where this codebase's own config error
messages send a reader — `loadFile`'s unknown-key error (`config.go:249`) says
"see docs/configuration.md for valid keys" — so a key missing from that file is
worse than a key missing from a comment: it breaks the error message's own
promise.

## 6. Consider whether the key should be file-only

Not every key belongs behind a flag or an environment variable just because it
could be. `Agent.AllowRemoteRouteMutation` (`config.go:72-86`) is deliberately
settable only in a config file — no flag, no env var — because anything that can
prepare a process's environment (a service unit, a container definition, a
wrapper script) could otherwise flip a security-relevant setting invisibly. A
file somebody edited on purpose is a narrower, more reviewable surface than "any
process that can set an environment variable before exec." If your new key
gates something a caller could otherwise turn on by accident or by a wider
mechanism than intended, keep it file-only and say why in its doc comment, the
same way `AllowRemoteRouteMutation`'s comment does.

## 7. Add test coverage

`internal/config/config_test.go` (and its siblings — `naming_test.go`,
`ports_test.go`, `reverse_test.go`, `vhost_limit_test.go`, `dialable_test.go`)
follow one convention: one `Test<Behavior>` function per case, table-driven where
several inputs share a shape. For a new key, the precedent to follow is
`TestPrecedenceDefaultLessThanFileLessThanEnv` (`config_test.go:547-566`), which
proves the three-source ordering — default, then file, then environment — for
`log.level` specifically. A new scalar key with an env override should have an
equivalent test proving the same ordering holds for it; a key with added
`Validate` logic needs a test proving the rejection, following
`TestBadRouteNameHardError`'s shape (`config_test.go:485`) as a model for an
error case, or `TestBadRouteNameIsWarningUnderClientRole`'s shape
(`config_test.go:512`) if the check is advisory outside the active role rather
than a hard error.
