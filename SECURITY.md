# Security policy

## Reporting a vulnerability

Please report security issues through GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/mauriciomem/quic-link/security/advisories/new)**.
That channel is private until an advisory is published.

Do not open a public issue for something exploitable.

This is a single-maintainer project. A first response should be expected in days
rather than hours, and there is no service commitment beyond best effort.

## Supported versions

Only the latest release. This project is pre-1.0: the wire protocol, the CLI
surface and the configuration schema are all still moving, and fixes land on
`main` and in the next tag rather than being backported.

## What the security model actually is

Worth stating plainly, because it is unusual and it determines which reports are
in scope.

**Authentication is mutual raw-public-key pinning.** Each end holds an Ed25519
key and pins the other's public key; the pins are exchanged out of band, once.
There is no certificate authority, no name validation, and nothing expires. A
peer is trusted because its key matches a pin, and for no other reason. TLS chain
verification is deliberately disabled on the pinning path, and the exact-key
check that replaces it is strictly stronger than chain verification would be —
so a static-analysis finding on that line is a false positive by design.

**There is no unauthenticated listener, in any mode.** Authentication is
mandatory everywhere, including debug paths.

**Every privileged operation lives in `sudo quic-link init`**, which writes
exactly one root-owned file per platform and is reversible with `init --undo`.
No runtime command escalates or prompts for elevation. The daemon and the agent
run unprivileged and bind no privileged port.

**Verifying what you downloaded.** Release archives carry SLSA build provenance:

```bash
gh attestation verify quic-link-*.tar.gz -R mauriciomem/quic-link
```

That asks GitHub whether the archive was built by this repository's release
workflow from a specific commit. It needs no keys. The build is also
reproducible: the same tag built with the same toolchain produces byte-identical
archives, so you can rebuild and compare digests instead of trusting the
attestation alone.

## Known limitations — in scope to report, but already known

Reports on these are welcome as *severity* arguments or exploit demonstrations,
but the behaviours themselves are recorded and deliberate.

- **Authenticated-peer resource exhaustion.** The agent spawns a goroutine per
  accepted connection with no cap, and in-flight QUIC handshakes are not bounded.
  The pin check happens inside the TLS handshake, so an *unauthenticated* peer
  never reaches this — it is a limit on what an already-trusted peer can consume.
- **Authorization is allow-all for reads.** The check-point exists in the code
  path and is enforced, but the default policy admits any authenticated peer to
  any configured target. Per-key, per-target access control is designed and not
  yet built.
  **Mutating control-plane calls are separately gated**: publishing or
  withdrawing a name requires the agent's operator to have opted in explicitly,
  and is refused twice over — the policy declines it *and* the capability is not
  built unless enabled. The authorization rule is an allowlist of what is safe to
  serve, so a method nobody classified is refused by default rather than
  permitted.
- **The naming plane assumes a single-operator host.** The DNS responder answers
  any local process, so another user on a shared machine can enumerate the
  configured server names. This is inherent to split-DNS and matches the
  same-uid boundary the daemon's control socket already relies on.
- **Names are not a secure browser context.** A `*.internal` name is not a
  trusted origin, so browser features gated on secure contexts are unavailable
  through it even though `127.0.0.1:<port>` would provide them. No TLS is
  terminated locally.
- **A remote peer's session survives, an in-flight stream does not.** Reconnection
  is automatic; a stream interrupted by a network fault is not resumed.

## Out of scope

- Anything requiring an attacker to already run code as the operator's own user.
  A same-uid process can read the identity key directly; the socket permissions
  and peer-credential check are defence in depth against a misconfiguration, not
  a boundary against that.
- Denial of service against a peer you are authenticated to.
- Vulnerabilities in dependencies with no reachable call path from this code.
  `govulncheck` runs in CI and gates on *reachable* advisories; an unreachable
  one in the module graph is tracked, not treated as an incident.
