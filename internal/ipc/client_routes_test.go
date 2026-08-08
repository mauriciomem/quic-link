package ipc_test

import (
	"errors"
	"testing"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// TestClientRoutesJSON_Success proves the client-side RoutesJSON call
// returns the provider's body verbatim and threads the server name through
// to the request unchanged — the same round trip TestRPCRoutes_Success
// proves at the raw-frame level, now through the Client API a real CLI verb
// would actually call.
func TestClientRoutesJSON_Success(t *testing.T) {
	want := []byte(`{"schema":1,"server":"srv1","routes":[{"target":"ssh","address":"tcp://127.0.0.1:22","builtin":true}]}`)
	stub := newStubRoutes()
	stub.body = want
	sock, _ := startTestServerWithRoutes(t, &stubStatus{data: []byte(`{}`)}, &stubPool{}, stub)

	got, err := ipc.NewClient(sock).RoutesJSON("srv1")
	if err != nil {
		t.Fatalf("RoutesJSON: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("body = %s, want %s", got, want)
	}

	select {
	case server := <-stub.calls:
		if server != "srv1" {
			t.Errorf("provider saw server = %q, want %q", server, "srv1")
		}
	default:
		t.Fatal("RoutesJSON was never called on the provider")
	}
}

// TestClientRoutesJSON_ErrDaemonAbsent proves that dialing a socket with no
// listener returns ErrDaemonAbsent, matching StatusJSON's behaviour for the
// identical condition (TestClientErrDaemonAbsent).
func TestClientRoutesJSON_ErrDaemonAbsent(t *testing.T) {
	dir := t.TempDir()
	c := ipc.NewClient(dir + "/missing.sock")
	_, err := c.RoutesJSON("srv1")
	if !errors.Is(err, ipc.ErrDaemonAbsent) {
		t.Errorf("got %v, want ErrDaemonAbsent", err)
	}
}

// TestClientRoutesJSON_RelaysRoutesError proves a *RoutesError the provider
// returned server-side (status and message) survives the client round trip
// intact — this is the mechanism the CLI relies on to print the daemon's own
// distinguishing message and exit with the daemon's own status, rather than
// a generic "routes rpc failed" string that has lost the distinction.
func TestClientRoutesJSON_RelaysRoutesError(t *testing.T) {
	stub := newStubRoutes()
	stub.err = &ipc.RoutesError{Status: 3, Msg: `server "srv1" is disabled; set enabled = true in the config to use it`}
	sock, _ := startTestServerWithRoutes(t, &stubStatus{data: []byte(`{}`)}, &stubPool{}, stub)

	_, err := ipc.NewClient(sock).RoutesJSON("srv1")
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v, want *ipc.RoutesError", err)
	}
	if re.Status != 3 {
		t.Errorf("Status = %d, want 3", re.Status)
	}
	want := `server "srv1" is disabled; set enabled = true in the config to use it`
	if re.Msg != want {
		t.Errorf("Msg = %q, want %q", re.Msg, want)
	}
}

// TestClientRoutesJSON_NoProviderConfigured proves a daemon that never
// called SetRoutes still returns a clean error to the client, not a hang or
// a panic surfacing as a connection reset.
func TestClientRoutesJSON_NoProviderConfigured(t *testing.T) {
	sock := startTestServer(t, &stubStatus{data: []byte(`{}`)}, &stubPool{})
	_, err := ipc.NewClient(sock).RoutesJSON("srv1")
	if err == nil {
		t.Fatal("expected an error when no RoutesProvider is configured")
	}
}
