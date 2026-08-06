package names_test

import (
	"testing"

	"go.uber.org/goleak"
)

// A leaked goroutine here fails every test in the package, which is what makes
// the read loops' shutdown discipline enforceable rather than aspirational.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
