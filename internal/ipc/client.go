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
// DoctorJSON asks the daemon what only it can answer. probe is a label just
// looked up through the system resolver; the reply says whether that lookup
// reached the responder.
func (c *Client) DoctorJSON(probe string) ([]byte, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := Request{SocketSchema: SocketSchema, Kind: "rpc", Method: "doctor"}
	if probe != "" {
		req.Meta = map[string]string{"probe": probe}
	}
	if err := writeRequest(conn, req); err != nil {
		return nil, err
	}
	resp, err := readResponse(conn)
	if err != nil {
		return nil, err
	}
	if resp.Status != 0 {
		return nil, fmt.Errorf("%s", resp.Msg)
	}
	return resp.Body, nil
}

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

// AttachStatusError is returned by Client.Attach when the daemon's ack carries
// a non-zero status. Status is already the final process exit code (the daemon
// computed it from the agent's response). The CLI passes Status directly to
// os.Exit; Msg is the agent's verbatim refusal message for stderr.
type AttachStatusError struct {
	Status int
	Msg    string
}

// Error implements the error interface.
func (e *AttachStatusError) Error() string {
	return fmt.Sprintf("attach refused (status %d): %s", e.Status, e.Msg)
}

// Attach opens an attach connection to the daemon for server/target, sends the
// attach request with the provided meta (e.g. reqid), and reads the ack
// response. On a zero-status ack it returns the live socket conn for the caller
// to splice — the conn is NOT closed (the caller owns it and must close it when
// the splice is done). On a non-zero ack it closes the conn and returns an
// *AttachStatusError. A daemon-absent condition returns ErrDaemonAbsent so the
// caller can fall back to a direct dial.
func (c *Client) Attach(server, target string, meta map[string]string) (net.Conn, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}

	req := Request{
		SocketSchema: SocketSchema,
		Kind:         "attach",
		Server:       server,
		Target:       target,
		Meta:         meta,
	}
	if err := writeRequest(conn, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ipc: write attach request: %w", err)
	}

	// Bound the ack read with a short deadline so a hung daemon does not
	// block the caller forever. The ack is just one CBOR frame; 10s is ample.
	// No deadline is set after the ack: the returned conn is a live splice
	// that may legitimately idle for hours.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ipc: set ack deadline: %w", err)
	}
	resp, err := readResponse(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ipc: read attach ack: %w", err)
	}
	// Clear the deadline so the returned conn is unrestricted for the splice.
	_ = conn.SetReadDeadline(time.Time{})

	if resp.SocketSchema != SocketSchema {
		conn.Close()
		return nil, fmt.Errorf("%w: daemon speaks schema %d, client expects %d",
			ErrSchemaMismatch, resp.SocketSchema, SocketSchema)
	}
	if resp.Status != 0 {
		conn.Close()
		return nil, &AttachStatusError{Status: int(resp.Status), Msg: resp.Msg}
	}

	// Return the raw conn so the caller can call conn.(*net.UnixConn) if it
	// needs CloseWrite for half-close semantics. The concrete type from
	// net.Dial("unix", ...) is *net.UnixConn, which implements CloseWrite.
	return conn, nil
}
