# Package map

This is the code-structure companion to [`docs/architecture.md`](../architecture.md).
That page explains the conceptual model — two roles, one binary, the connection
model, life of a byte. This page maps that model onto the actual source tree:
one heading per package a contributor would edit by hand, what it owns, and why
it is separate from its neighbors. Two packages have no heading of their own:
`internal/control/proto` (protoc-generated from `control.proto`, covered under
`internal/control`) and `internal/transport/mem` (test infrastructure, covered
under `internal/transport`, its parent).

Every description below is grounded in that package's own doc comment (most
packages have a `// Package X ...` comment at the top of one file) or, where none
exists, in a representative file's actual declarations. If a package's doc comment
disagrees with this page, the doc comment wins — read it directly.

This describes how the codebase is structured today, for anyone reading the
source or building from it. It is not an invitation to open a pull request — see
[`CONTRIBUTING.md`](../../CONTRIBUTING.md) for the project's current stance on
external contributions.

## `cmd/quic-link`

The only package that imports `cobra` and owns CLI concerns: argument parsing,
flag definitions, `--help` text, exit codes, and the local IPC calls that talk to
a running daemon. Its own doc comment (`main.go`) lists 10 verbs (one, `stdio`,
marked hidden) and mentions two more in prose as deprecated aliases (`serve`
for `agent`, `connect` for `daemon --server NAME`). `root.go`'s `AddCommand`
call registers 16 top-level commands. It is deliberately thin — the
accept-loop and protocol logic it wraps live in `internal/`, not here, so a
verb's `.go` file is mostly wiring. See [`add-a-verb.md`](add-a-verb.md) for
the shape a new verb takes.

## `internal/backoff`

Provides the reconnect schedule shared by both sides of a tunnel. Whichever
end dials owns reconnection: the client in forward mode, the agent in reverse
mode. The policy cannot live in either side's own package without one
importing the other, so it lives here instead. One small package, one
exported schedule.

Three consumers use it differently: `internal/tunnel` takes it as a parameter
and runs it. `internal/daemon` aliases its policy type and default for the
client-side pool. `cmd/quic-link` (the `agent` verb, for reverse mode) passes
`backoff.Default()` straight through to `tunnel.DialAndServe`.

## `internal/buildinfo`

Holds the CLI's own build-time version metadata: two variables meant to be
overridden at link time via `-ldflags -X ...`. An un-stamped local build keeps
placeholder values instead of an empty string.

Explicitly unrelated to the wire protocol version in `internal/proto`: one
answers "what tool build is this," the other "what wire protocol does it
speak." The package comment is emphatic that the two must never be conflated.

## `internal/config`

Loads, merges, and validates configuration. Source order is built-in
defaults < config file < environment variables; flag overrides are applied
by the caller after `Load` returns.

The config file format is TOML. `docs/configuration.md` is the schema's
canonical description, and `Config`'s own doc comment says so.

Structural errors (unknown keys, wrong types) are caught by strict decoding.
Semantic errors (missing required fields, invalid pins, over-limit tables)
are caught by `Validate`. See
[`add-a-config-key.md`](add-a-config-key.md) for the walkthrough.

## `internal/control`

Implements the control plane: gRPC served over the single per-session control
stream. It provides the `net.Conn` adapter that lets gRPC's HTTP/2 framing run
over one QUIC stream, the single-connection `net.Listener` the agent-side gRPC
server needs, and the server/client wiring for the Control service (status
queries, vhost publish/withdraw).

It deliberately does not import `internal/router`. An administrative RPC and a
data-plane dial target are two different assets, each guarded by its own
boundary. `control`'s own types (`PeerIdentity`, `RouteDetail`) mirror
router's shapes rather than sharing them, so a change to one side's identity
representation cannot silently move to the other.

`internal/control/proto` is its sibling: the protoc-generated message and
gRPC-stub code (`controlpb`) built from `control.proto`, imported by `control`
but never edited directly. Nobody hand-edits generated code, so it is covered
here rather than getting its own heading.

## `internal/daemon`

Implements the lifecycle, session pool, and status snapshot for the
client-side daemon process. It orchestrates the session pool, the IPC socket
server, and the signal-driven shutdown sequence, but implements no protocol
or allocator itself. Those live in `internal/ipc`, `internal/tunnel`, and
`internal/config` respectively.

Its own doc comment catalogs every goroutine family it owns: dial loops, the
IPC accept loop, per-connection handlers, edge accept loops, splice
goroutines, the signal-cancel goroutine. It states that none is
fire-and-forget: every one has a clear exit path rooted in a cancelled
context or a closed listener. That claim is verified by `goleak` in the
package's own test suite (12 source files, 32 test files), which tracks with
owning the process's entire shutdown discipline.

## `internal/edge`

Owns the local loopback listeners for the daemon's lifetime. Each enabled
server gets one `localPortEdge`, holding a bound TCP listener each for the
`ssh` and `docker` targets. Accepted connections splice directly to a QUIC
stream via `tunnel.DoAttach`, no IPC round trip, because the local
application already connected straight to the port.

Port acquisition steps in ten-port blocks, so a server's two services always
occupy a predictable adjacent pair. The listeners are held open for the
daemon's whole lifetime — a hold-the-listener pattern that eliminates the
probe-then-bind TOCTOU race the foreground `connect` path has.

## `internal/fwd`

Implements the accept-loop core of the `fwd` verb: an ad-hoc local TCP listener
that forwards every accepted connection to a named route-table target through the
daemon's IPC socket, one fresh attach per connection. `cmd/quic-link/fwd.go` is
the thin cobra wrapper around it. Deliberately kept separate from `cmd/quic-link`,
which carries no goroutine-leak guard: this package's accept loop is
lifecycle-sensitive code, and its own doc comment notes it was born under a
`goleak` guard (`fwd_test.go`'s `TestMain`) from its first commit rather than
bolted on later.

## `internal/identity`

The single source of truth for the pin credential and the raw-public-key
pinning TLS handshake. A pin is
`base64std(SHA-256(SubjectPublicKeyInfo DER))` over an Ed25519 key. Each
endpoint holds an Ed25519 keypair wrapped in a runtime self-signed X.509
certificate used only as a TLS key carrier: verification ignores every X.509
semantic (chain, expiry, SANs) and compares pins directly.

Split across three files by its own doc comment's account: `pin.go` (the
credential and its parsing), `key.go` (key generation, loading, on-disk
persistence), `tls.go` (the carrier certificate and the pinning `tls.Config`
builders).

## `internal/ipc`

Implements the local unix-socket protocol between CLI verbs (`status`, `ssh`,
`fwd`, `docker-env`) and the daemon process. Two kinds of traffic ride the
same socket:

- **RPC** (`kind="rpc"`): one request, one response, connection closes.
- **Attach** (`kind="attach"`): the daemon opens a QUIC stream, sends one ack,
  then splices the socket connection directly to it. `handleAttach` in
  `server.go` calls `tunnel.DoAttach`, which runs the real bidirectional
  splice. (The package's own top-of-file doc comment predates this and still
  describes the splice as future work returning a stub ack — that comment is
  stale; the splice is wired.)

Frames use CBOR with a version|length|payload envelope, distinct from the
wire protocol's own framing. The same doc comment is explicit that this
mirrors the wire protocol's philosophy without sharing its bytes or version
space. A `socket_schema` field in every frame lets a stale daemon be detected
and refused before any action is taken.

## `internal/names`

Owns the client-side naming layer: which hostnames this machine answers for, and
what they mean. Its own doc comment draws a hard line: nothing here opens a
session, consults a pool, or knows whether a server is reachable, because a name
resolving and a service being up are different questions answered by different
layers — that split is what lets a browser report "cannot connect" instead of
"cannot resolve" when a server is merely down. Internally it covers DNS answers
(`dns.go`), TLS SNI parsing to route unencrypted-looking bytes without decrypting
them (`sni.go`), and the actual listening servers (`server.go`).

## `internal/probe`

Implements the `ping` subcommand's measurement logic: opening a fresh QUIC
connection, timing the handshake, and reporting round-trip time. Small and
single-purpose: one source file, one test file. `ping` deliberately does not
share the daemon-aware resolution machinery every other verb uses; see
[`add-a-verb.md`](add-a-verb.md) for why.

## `internal/proto`

Implements the wire protocol itself, version 1: length-prefixed frames carrying
CBOR payloads. A stream begins with exactly one header frame (initiator to
acceptor) and one response frame (acceptor to initiator) before any payload
flows. `ProtoVersion` is the frame version byte and moves with any change to
bytes or semantics — the number `quic-link version` reports as "wire protocol
version," distinct from the CLI's own build version in `internal/buildinfo`.

## `internal/router`

Resolves a logical name a client asked for into a network address, and decides
whether the connection asking for it may have it. A client never names an
address directly. It names a target name or a host, so this package is the sole
resolution-and-authorization boundary on the agent side.

Two tables answer two separate namespaces: the route table (short
operator-chosen names like `ssh`, `docker`) and the vhost table (hostnames,
including wildcards, published in configuration or at runtime over the
control plane). The vhost table is bounded by `MaxVhosts` (128 today), counted
across configuration and runtime publishes together.

Every entry carries a `Provenance` recording where it came from. Provenance
never carries caller identity, so the table cannot tell one authorized
caller's runtime entry from another's. That is why only a
control-plane-published name can be withdrawn, and why any authorized caller
can withdraw any other's.

Authorization is a separate step after resolution: `Router` asks its `Policy`
whether the peer may have what it resolved. The default `Policy` permits
every authenticated peer, but the check-point itself runs unconditionally on
every dial.

## `internal/setup`

Owns the files `quic-link init` installs on the machine, and the checks that
decide whether installing them will actually work. Every file it writes
carries a marker on its first line. The marker is what distinguishes a file
this tool may rewrite or remove from one that belongs to somebody else and
happens to share a path — its own doc comment puts it plainly: without the
marker, "undo" would be indistinguishable from "delete a stranger's
configuration."

## `internal/transport`

Defines the `Transport` abstraction quic-link uses for the underlying connection:
`Stream`/`Conn` types shaped around `io`/`net` primitives rather than
QUIC-specific ones. QUIC is the only concrete implementation shipped today; the
interfaces are kept transport-agnostic in shape so a second transport could
implement them without a redesign, though none is planned. `internal/transport/mem`
is a sibling package providing an in-memory implementation used purely as test
infrastructure — it lets the dial-and-reconnect machinery be tested without UDP
sockets, QUIC crypto, or OS privileges.

## `internal/tunnel`

Wires together the transport layer and local TCP services: the code that opens a
stream, sends the header, awaits the response, and splices bytes in both
directions — the mechanics behind "Life of a byte" in `docs/architecture.md`.
Heavily tested by test-file count (4 source files, 20 test files), which
tracks with it sitting on the reconnect and splice path every session depends
on.

## The overall shape

`cmd/quic-link` is the only package that imports cobra and owns CLI concerns:
argument parsing, help text, exit codes. Everything under `internal/` is the
implementation.

`internal/daemon`, `internal/tunnel`, and `internal/control` are the core
session machinery. `daemon` orchestrates, `tunnel` moves bytes, `control`
carries administrative RPCs over the same connection.

The rest are focused utilities, each answering one question without reaching
into any other package's job:

| Package | Answers |
|---|---|
| `backoff` | How to retry |
| `buildinfo` | What version am I |
| `config` | What does the config say |
| `edge` | Where do I listen |
| `fwd` | How do I forward a plain TCP port |
| `identity` | Who am I |
| `ipc` | How do I talk to the daemon locally |
| `names` | What do I answer to |
| `probe` | How do I measure a handshake |
| `proto` | What do these bytes mean |
| `router` | Where does this name go |
| `setup` | What do I own on disk |
| `transport` | How do I move bytes across a connection |
