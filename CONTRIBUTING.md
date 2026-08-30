# Contributing

quic-link is a single Go binary that tunnels SSH and Docker traffic between a
client-side daemon and a server-side agent over one mutually-authenticated
QUIC connection. See `README.md` for what it does and how to use it, and
`docs/architecture.md` for how it's built.

## Current status: not open for contributions yet

This is a single-maintainer project in active development. The wire protocol,
CLI surface, and config schema are all still moving, and reviewing external
changes against a design that hasn't settled yet would slow both of us down.
Pull requests aren't being accepted at this stage.

That's a "not yet," not a "no." Once the core is stable, contributions will be
genuinely welcome, and interest in the project now is appreciated.

One exception, so it does not look like a contradiction: automated dependency
update pull requests are expected and welcome. They are how security fixes and
version bumps reach a single-maintainer project without someone remembering to
check by hand.

## What you can do in the meantime

- **Try it and report your experience.** Real usage on real machines is the
  most useful feedback there is.
- **Open an issue for a bug.** Include your OS, the command you ran, and what
  you expected versus what happened.
- **Open an issue for a question.** If something in the README or the CLI
  `--help` output is unclear or looks wrong, that's worth flagging even if it
  turns out to be intentional.
- **Watch the repository** if you want to know when contributions open up.

## Build and test

If you want to build from source or read the code, this is the whole loop:

```bash
./scripts/test.sh            # build, gofmt, vet, the suite, and the result counts
./scripts/test.sh --race     # the same, with the race detector
./scripts/cross.sh           # every platform still compiles
golangci-lint run ./...      # the static-analysis gate
```

`make test`, `make test-race`, `make cross` and `make lint` are aliases for those,
and the CI workflow calls the same scripts, so a green run locally means the same
thing a green run in CI does.

If you are reading the source rather than just building it, `docs/contributing/`
has four pages worth knowing about:

- [`package-map.md`](docs/contributing/package-map.md) — what each package owns
  and why it is separate from its neighbors.
- [`add-a-verb.md`](docs/contributing/add-a-verb.md) — how a CLI subcommand is
  structured, walked through on an existing one.
- [`add-a-config-key.md`](docs/contributing/add-a-config-key.md) — how a config
  field is declared, defaulted, validated, and documented.
- [`testing-conventions.md`](docs/contributing/testing-conventions.md) — what's
  underneath `./scripts/test.sh`, including a hazard worth knowing before you
  trust a red result.

The linter is pinned to the version CI uses, because one that updates itself turns
an unrelated push into a red build on code nobody touched:

```bash
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
  | sh -s -- -b "$(go env GOPATH)/bin" v2.13.1
```

Pass no flags to it. Which linters run, and how much of the report is shown, are
both settled in `.golangci.yml` — deliberately, so that a bare run and CI cannot
disagree. Two of the defaults there are worth knowing: the report caps are lifted,
because the defaults of 50 per linter and 3 per repeated issue silently truncate,
and use of a deprecated symbol is only tolerated in test files, so a deprecated
call reaching production code fails the build.

Two details worth knowing before you read the script:

`-count=1` is always passed, which disables test caching so goroutine-leak checks
(`goleak`) run on every execution.

The script also checks how many test results were *reported*, against
`scripts/expected-counts.txt`. A suite can fail while naming no failing test, and
it can quietly stop reporting results it used to report — that happened here once,
when a test closed the test process's own stdout and twenty results vanished while
the suite still said `FAIL`. If you add or remove a test, update that file in the
same commit; if the number moves and you did not expect it, something stopped
reporting.

A plain `go build` produces a binary where `quic-link version` reports `dev`
and `none`. To stamp a real version and commit into the binary, pass them at
build time via linker flags:

```bash
go build -ldflags "-X github.com/mauriciomem/quic-link/internal/buildinfo.version=<VER> -X github.com/mauriciomem/quic-link/internal/buildinfo.commit=<SHA>" ./...
```

## Where to ask

Open an issue. That's the front door for bug reports, questions, and anything
else related to the project.
