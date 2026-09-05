package main

// stdout_capture_test.go proves, at the byte level, that ping's
// all-probes-failed path writes nothing to process stdout. This is the
// runtime counterpart to what stdout_discipline_test.go's textual scan
// cannot be: that test only reads test-file source and would pass even if a
// verb printed a secret to stdout on every run.

import (
	"context"
	"testing"
)

// TestPingAllProbesFailed_WritesNothingToStdout dials an address with a
// context already cancelled, so the dial fails on its first attempt without
// depending on network timing. With every probe failed, pingRun returns
// before its stats section's fmt.Printf calls ever run (ping.go, the
// successful == 0 branch), so the captured stdout must be empty.
func TestPingAllProbesFailed_WritesNothingToStdout(t *testing.T) {
	// No t.Parallel(): captureStdout swaps the process-global os.Stdout,
	// which is incompatible with running concurrently with any other test
	// doing the same.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	keyFile := writeTestKey(t)
	pin := mustTestPin(t)

	stdout, err := captureStdout(t, func() error {
		return pingRun(ctx, "192.0.2.1:7443", 1, keyFile, pin)
	})
	if err == nil {
		t.Fatal("pingRun succeeded against an address nothing answers; want every probe to fail")
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on the all-probes-failed path", stdout)
	}
}
