package ipc

import (
	"fmt"
	"net"
)

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
