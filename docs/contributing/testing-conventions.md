# Testing conventions

[`CONTRIBUTING.md`](../../CONTRIBUTING.md) already covers the basic build/test
loop — `./scripts/test.sh`, `./scripts/test.sh --race`, the linter version, the
`-ldflags` version-stamping recipe. Read that first. This page goes deeper into
the mechanics behind that loop and one hazard worth knowing before you rely on a
red or green result.

This describes how the codebase actually tests itself today, for anyone reading
the source or building from it. It is not an invitation to open a pull request —
see `CONTRIBUTING.md` for the project's current stance on external contributions.

## What `scripts/test.sh` actually does

The script (well-commented in its own right; read it directly for the exact
sequence) runs, in order: `go build`, a `gofmt -l` check that fails the run if
any file is not formatted, `go vet`, the test suite itself, and finally a count
check against `scripts/expected-counts.txt` (see below). It checks `go test`'s
exit status first and independently of the count — a build failure, a panic, or
a timeout all lower the reported count while also failing the run on their own,
so the count is a canary for something narrower: results going missing without
the run itself reporting failure.

The suite runs twice with two different scopes — `./cmd/quic-link/` and `./...`
— each checked against its own expected count in `expected-counts.txt`. That
split exists because `cmd/quic-link` is the one non-hermetic package in the tree
(see below), so isolating its count from the tree-wide one makes a drift in
either scope traceable to the scope it actually happened in.

## The `expected-counts.txt` canary

`scripts/test.sh` counts test results actually *reported* — the `--- PASS:`,
`--- SKIP:`, and `--- FAIL:` lines Go writes at column zero under `go test -v` —
and compares that count against the numbers recorded in
`scripts/expected-counts.txt`. This is the single most surprising local
convention in the tree, and it exists for a concrete, previously-encountered
reason: a test once closed the test process's own stdout, and twenty results
went unreported while the suite still printed `FAIL` at the end. An exit status
alone cannot see that kind of silent gap; a count can.

The consequence for day-to-day work: **if you add or remove a test, update
`scripts/expected-counts.txt` in the same commit.** If the number moves and you
did not intend it to, something stopped reporting, and the fix is to find out
why, not to update the file to make the check pass. Subtests (`t.Run` cases) are
deliberately not counted — Go indents their result lines and the check is
anchored to column zero — so adding a case to an existing table-driven test does
not move either number; only a new or removed top-level `func Test...` does.

## `-count=1` and `goleak`

Every test invocation passes `-count=1`, disabling Go's test result cache. This
matters specifically because of `goleak`: a cached "pass" from an earlier run
would never re-execute the goroutine-leak check, silently defeating it. Passing
`-count=1` on every run is what keeps `goleak` honest — a green result always
means the leak check actually ran this time, not that Go remembered it once did.

## The non-hermetic daemon hazard

`cmd/quic-link`'s test suite is not hermetic against a live `quic-link` daemon
holding the per-user IPC socket. If a real daemon process is running on the
machine when the suite starts, roughly 17 tests in that package fail —
spuriously, for a reason that has nothing to do with whatever change you are
actually testing. This is a real, currently open limitation, not a hypothetical
one, and there is no fix for it in this codebase today.

The mitigation is simple and worth doing as a habit: **check for, and stop, any
running `quic-link` daemon before running `scripts/test.sh` or `go test ./...`.**
If you hit a `cmd/quic-link` failure that looks unrelated to what you changed,
that is the first thing to rule out before spending time on it — a failure that
disappears once the daemon is stopped was never about your change.

## Other targets worth knowing

The `Makefile` is a thin dispatcher — every target forwards to a script in
`scripts/`, and each recipe is a single line. Two reasons are recorded in its own
header comment: CI's macOS runners ship GNU Make 3.81 (2006, because Apple will
not distribute GPLv3), so a rule that works locally can still fail on a runner,
and CodeQL's Go analysis runs bare `make` as its build step, which makes the
default goal (`build`) part of a security scan's behavior — so it stays a plain
build and nothing more.

Beyond `build`, `test`, and `test-race`, the targets are: `lint`
(`golangci-lint run ./...`, pinned per `CONTRIBUTING.md`; `.golangci.yml`
deliberately lifts the default report caps, since the defaults of 50 findings
per linter and 3 per repeated issue silently truncate a real report); `vuln`
(`govulncheck ./...`, run for its text output on purpose — the JSON mode exits 0
even when it finds something, which would make it useless as a gate); `proto`
(runs `buf`: style rules first, then the check that matters — whether the wire
protocol stayed compatible with the default branch); `bench` (accepts
`COUNT=N` to average more runs: `make bench COUNT=20`); `bench-check` (only
proves the benchmarks still compile and run, because timings on a shared CI
runner are too noisy to gate on — this is what CI actually runs, never `bench`
itself); `cross` (every supported platform still compiles); `release`
(`VERSION=v0.1.0`, builds release artifacts locally exactly as CI does and
verifies they are reproducible); and `clean`.

## Test-file layout

Tests sit beside the code they test, as `<name>_test.go` in the same package and
directory — there is no separate top-level test tree. Test names describe the
behavior under test, not the implementation: `cmd/quic-link/status_routes_test.go`'s
`TestStatusRoutes_ExtraArgWithoutRoutesFlag_Exit2` is representative of the
house style — specific enough that a failure's name alone says what broke,
without needing to open the file.
