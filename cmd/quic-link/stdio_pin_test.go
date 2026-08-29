package main

import (
	"testing"
)

// TestStdio_AcceptsCanonicalPinFlag is the control case: a pin already in its
// canonical form must still be accepted past the pin check, exactly as
// before this refusal was added. The unreachable dial address means this
// still ends in a non-2 exit code, but the failure must come from the dial
// attempt, not from pin parsing — i.e. NOT exit 2.
func TestStdio_AcceptsCanonicalPinFlag(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	canonical := mustTestPin(t)
	path := writeTestConfig(t, "schema = 1\n")

	err := runVerb([]string{
		"--config", path, "stdio",
		"--server", "127.0.0.1:1", "--pin", canonical,
		"anyserver", "ssh",
	})
	if exitCode(err) == 2 {
		t.Fatalf("stdio --pin with a canonical pin: got exit 2 (pin rejected); "+
			"want it to pass the pin check and fail at dial instead: %v", err)
	}
}

// TestStdio_RefusesNonCanonicalPinFlag is the regression test for the pin
// strictness gap: stdio's --pin flag path used identity.ParsePin, which
// repairs a non-canonical spelling of a valid digest rather than refusing
// it, while every sibling pin entry point (--authorized-client,
// --server-pin, ping --pin, and every config-file pin) already refuses.
// stdio is not an obscure corner: it is exactly what ssh/attach exec as a
// ProxyCommand, with --pin threaded through verbatim, so it is the
// most-travelled flag path of the three that take a raw pin flag.
//
// No daemon is started, so this exercises the direct-dial path where the
// pin flag is parsed — the same site the fix must change.
func TestStdio_RefusesNonCanonicalPinFlag(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	canonical := mustTestPin(t)
	variant := flipTrailingBit(t, canonical)
	path := writeTestConfig(t, "schema = 1\n")

	err := runVerb([]string{
		"--config", path, "stdio",
		"--server", "127.0.0.1:1", "--pin", variant,
		"anyserver", "ssh",
	})
	if exitCode(err) != 2 {
		t.Fatalf("stdio --pin with a non-canonical spelling: want exit 2, got %d: %v",
			exitCode(err), err)
	}
}
