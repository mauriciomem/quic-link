package proto

// ExitCodeForStatus maps an agent response status to a process exit code.
// This is the single canonical mapping: 0 for success, 4 for authorization
// denied, 5 for any flavor of remote refusal (unknown target, dial failure, or
// agent draining), and 1 for anything else.
//
// Both the CLI's local exitCodeForStatus wrapper and the IPC server's attach
// relay call this function so the mapping is never duplicated.
func ExitCodeForStatus(s Status) int {
	switch s {
	case StatusOK:
		return 0
	case StatusUnauthorized:
		return 4
	case StatusUnknownTarget, StatusDialFailed, StatusDraining:
		return 5
	default:
		return 1
	}
}
