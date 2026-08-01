# Contributing

quic-link is a single Go binary that tunnels SSH and Docker traffic between a
client-side daemon and a server-side agent over one mutually-authenticated
QUIC connection. See `README.md` for what it does and how to use it, and
`ARCHITECTURE.md` for how it's built.

## Current status: not open for contributions yet

This is a single-maintainer project in active development. The wire protocol,
CLI surface, and config schema are all still moving, and reviewing external
changes against a design that hasn't settled yet would slow both of us down.
Pull requests aren't being accepted at this stage.

That's a "not yet," not a "no." Once the core is stable, contributions will be
genuinely welcome, and interest in the project now is appreciated.

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
go build ./...
go vet ./...
go test -race -count=1 ./...
```

`-count=1` disables test caching so goroutine-leak checks (`goleak`) run on
every execution.

## Where to ask

Open an issue. That's the front door for bug reports, questions, and anything
else related to the project.
