package ipc

import (
	"fmt"
	"net"
)

// RoundTrip opens a connection to sockPath, sends req, reads the response, and
// closes the connection. It is a test helper exposed so _test packages in other
// directories can exercise the IPC frame encoding without duplicating the
// low-level frame I/O.
func RoundTrip(sockPath string, req Request) (Response, error) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		if isNetRefused(err) || isNoSuchFile(err) {
			return Response{}, fmt.Errorf("%w: %v", ErrDaemonAbsent, err)
		}
		return Response{}, fmt.Errorf("ipc: dial %s: %w", sockPath, err)
	}
	defer conn.Close()
	return RoundTripConn(conn, req)
}

// RoundTripConn sends req on the already-open conn and returns the response.
// The conn is not closed. Useful in tests that want to dial manually.
func RoundTripConn(conn net.Conn, req Request) (Response, error) {
	if err := writeRequest(conn, req); err != nil {
		return Response{}, fmt.Errorf("ipc: write request: %w", err)
	}
	resp, err := readResponse(conn)
	if err != nil {
		return Response{}, fmt.Errorf("ipc: read response: %w", err)
	}
	return resp, nil
}
