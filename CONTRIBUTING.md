# Contributing

quic-link has a versioned wire protocol and a frozen status contract. Small changes can have non-obvious reach. Read this before opening a PR.

---

## Build and test gate

Every PR must pass these commands before requesting review:

```bash
go build ./...
go vet ./...
go test -race -count=1 ./...
```

`-count=1` disables test caching — goroutine-leak checks (`goleak`) run per-execution. If your package spawns goroutines, add `goleak.VerifyTestMain` to its `TestMain`.

---

## Start with the contract

Before writing code, define what the feature does externally:

- **New CLI verb:** write the synopsis, flags, stdout contract, and exit codes in `internal-docs/docs/` first.
- **New config key:** add it to the config schema. Unknown keys are a startup error.
- **New `status --json` field:** bump `schema` and update the golden file — see invariants below.

Unsure whether your change crosses a contract boundary? Open an issue first.

---

## Wire-change stop sign

Any change to frame layout, field semantics, or status codes is a **breaking change**:

1. Re-read the protocol spec in `internal-docs/docs/` before touching anything.
2. Bump `ProtoVersion` in `internal/proto` **and** the ALPN string in `internal/transport`.
3. Add a test vector in the same commit as the code.
4. Note the impact in your PR — both ends must be rebuilt simultaneously.

---

## Invariants

These are not style preferences. Violations break operator-visible contracts.

| Rule | What it means |
|---|---|
| **Typed errors, not `os.Exit`** | Verbs return typed errors; `main()` is the single place that maps them to exit codes. No `os.Exit` outside `main.go`. |
| **Godoc on every exported symbol** | Plain English answering "what is this?" or "what does it do / require / return on error?". No internal spec citations in `.go` files; RFC references are fine. |
| **Every goroutine has an owner and a teardown path** | If it is not in `internal/daemon`'s goroutine ownership table, it is a leak candidate. Decide who cancels its context before you start it. `goleak` enforces this in tests. |
| **`status --json` byte-shape is frozen** | No field additions, renames, or reordering without bumping `schema` and regenerating `testdata/status_golden.json`. Include the updated golden file in your PR. |
| **Authentication is always on** | No code path leads to an unauthenticated connection — no debug flag, no loopback exemption. Tests use `internal/transport/mem` with injectable peer certs; real TLS is not needed in unit tests. |
| **No secrets in tracked files, config, or logs** | Private keys live only at their on-disk 0600 path. Do not commit keys, tokens, passwords, or connection strings anywhere in the tracked repository. |

---

## Doc maintenance

When editing files in `internal-docs/docs/`:

- Every doc has a `Version`, `Last-updated`, `Status`, and `## Changelog`. Editing means adding a changelog line and bumping the version.
- Architecture decision records are **immutable once accepted**. Write a superseding record instead of editing an accepted one.

---

## Commits and PRs

- **Small vertical slices.** Each PR is independently runnable and testable.
- **Demo sentence.** PR description must include: "After this PR, `quic-link X` does Y."
- **Reference the acceptance item** your PR satisfies, if one exists.

---

## Where to ask

Open an issue. Design questions go to an issue (or a proposed decision record) before any implementation — not embedded in a PR.
