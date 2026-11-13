/**
 * @spec-handoff
 * @interface package pairing (internal/pairing) - join blob, exporter proof, messages, framing; no I/O
 * @behavior
 *   - Every test binary in this package runs under goleak.VerifyTestMain: no goroutine may outlive a test
 * @see ./blob_test.go
 * @see ./proof_test.go
 */

package pairing_test

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
