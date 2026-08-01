// Package buildinfo holds the CLI's own build-time version metadata. The two
// variables are meant to be overridden at link time via -ldflags "-X ...";
// an un-stamped local build (plain "go build" with no -ldflags) keeps the
// placeholder values below rather than reporting an empty string.
//
// A release build stamps both variables, for example:
//
//	go build -ldflags "\
//	  -X github.com/mauriciomem/quic-link/internal/buildinfo.version=v1.2.3 \
//	  -X github.com/mauriciomem/quic-link/internal/buildinfo.commit=abc1234"
//
// This is unrelated to the wire protocol version (proto.ProtoVersion): one
// answers "what tool build is this", the other "what wire protocol does it
// speak", and the two must never be conflated.
package buildinfo

// version and commit are set via -ldflags -X at build time. They are
// unexported so every read goes through the accessor functions below,
// keeping the mutable build-time state out of every other package's direct
// reach.
var (
	version = "dev"
	commit  = "none"
)

// Version returns the CLI's own semver, or "dev" for an un-stamped build.
func Version() string { return version }

// Commit returns the git commit the binary was built from, or "none" for an
// un-stamped build.
func Commit() string { return commit }
