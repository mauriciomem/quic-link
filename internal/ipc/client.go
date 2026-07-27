package ipc

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"syscall"
	"time"
)

// Client connects to the daemon socket and issues RPCs. Each method opens a
// fresh connection; the socket is connection-per-request (short-lived RPCs).
type Client struct {
	path string
}

// NewClient returns a Client that dials the unix socket at path.
func NewClient(path string) *Client {
	return &Client{path: path}
}

// dial opens a connection to the daemon socket. On ECONNREFUSED or a missing
// socket file it returns ErrDaemonAbsent so the caller can print a remedy.
func (c *Client) dial() (net.Conn, error) {
	conn, err := net.Dial("unix", c.path)
	if err != nil {
		if isNetRefused(err) || isNoSuchFile(err) {
			return nil, fmt.Errorf("%w: %v", ErrDaemonAbsent, err)
		}
		return nil, fmt.Errorf("ipc: dial %s: %w", c.path, err)
	}
	return conn, nil
}

// StatusJSON sends a status RPC and returns the raw JSON bytes from
// Response.Body. On schema mismatch it returns ErrSchemaMismatch.
func (c *Client) StatusJSON() ([]byte, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := Request{
		SocketSchema: SocketSchema,
		Kind:         "rpc",
		Method:       "status",
	}
	if err := writeRequest(conn, req); err != nil {
		return nil, fmt.Errorf("ipc: write status request: %w", err)
	}

	resp, err := readResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("ipc: read status response: %w", err)
	}

	if resp.SocketSchema != SocketSchema {
		return nil, fmt.Errorf("%w: daemon speaks schema %d, client expects %d",
			ErrSchemaMismatch, resp.SocketSchema, SocketSchema)
	}
	if resp.Status != 0 {
		// A schema-mismatch error arrives as a non-zero status response whose
		// SocketSchema field carries the daemon's actual schema. Check that
		// field rather than matching text in the message, which is fragile.
		if resp.SocketSchema != SocketSchema {
			return nil, fmt.Errorf("%w: daemon speaks schema %d, client expects %d",
				ErrSchemaMismatch, resp.SocketSchema, SocketSchema)
		}
		return nil, fmt.Errorf("ipc: status rpc failed (status %d): %s", resp.Status, resp.Msg)
	}

	return []byte(resp.Body), nil
}

// Probe sends a status RPC and returns nil on any valid response from a
// conforming daemon (schema match, any status). It is used by the
// single-instance check to determine whether a live owner is answering the
// socket. It returns ErrSchemaMismatch if the daemon's schema differs.
//
// Probe accepts a timeout that is set as an end-to-end deadline on the
// connection so the call is self-bounding: a hung or slow peer (e.g. a
// squatter that accepts but never responds) releases this call within the
// deadline rather than blocking indefinitely. The caller does not need a
// separate goroutine + timer; Probe is guaranteed to return within timeout.
//
// Note: the server-side openReadDeadline (5s) is a server-side resource
// bound on the opening header read. This client-side deadline is separate
// and is the caller's tool for bounding probe latency.
func (c *Client) Probe(timeout time.Duration) error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Set an end-to-end deadline so a hung peer never blocks this goroutine.
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	req := Request{
		SocketSchema: SocketSchema,
		Kind:         "rpc",
		Method:       "status",
	}
	if err := writeRequest(conn, req); err != nil {
		return fmt.Errorf("ipc: probe write: %w", err)
	}

	resp, err := readResponse(conn)
	if err != nil {
		return fmt.Errorf("ipc: probe read: %w", err)
	}

	if resp.SocketSchema != SocketSchema {
		return fmt.Errorf("%w: daemon speaks schema %d",
			ErrSchemaMismatch, resp.SocketSchema)
	}
	return nil
}

// isNoSuchFile reports whether err is a "no such file or directory" condition
// (the socket path does not exist at all). Matches both the syscall errno and
// the fs sentinel so the check works on every supported platform without
// string-comparing error messages, which is fragile across OS locales.
func isNoSuchFile(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, fs.ErrNotExist)
}
