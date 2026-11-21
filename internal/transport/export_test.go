package transport

// Test-only access to unexported pairing-dial classification for the
// black-box tests in package transport_test.
var (
	ClassifyPairDialError = classifyPairDialError
	ClassifyDialError     = classifyDialError
	ErrNoPairingWindow    = errNoPairingWindow
	ErrPairBlobMismatch   = errPairBlobMismatch
)
