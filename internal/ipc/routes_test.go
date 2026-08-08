package ipc_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// stubRoutes is a RoutesProvider returning a fixed body or error, configured
// per test. gotServer and gotCtx record what the handler actually passed
// through, so a test can assert the server name travelled correctly and a
// deadline was applied — recorded on a buffered channel, never a plain
// field, so a concurrent read from the test goroutine has a real
// synchronization edge instead of racing the handler goroutine that calls
// RoutesJSON.
type stubRoutes struct {
	body []byte
	err  error

	calls chan string // server name recorded per call, buffered
}

func newStubRoutes() *stubRoutes {
	return &stubRoutes{calls: make(chan string, 8)}
}

func (s *stubRoutes) RoutesJSON(ctx context.Context, server string) ([]byte, error) {
	select {
	case s.calls <- server:
	default:
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.body, nil
}

// TestRPCRoutes_Success proves a successful relay returns the provider's
// body verbatim at status 0, and that the server name from the request
// travelled through to the provider unchanged.
func TestRPCRoutes_Success(t *testing.T) {
	want := []byte(`{"schema":1,"server":"srv1","routes":[]}`)
	stub := newStubRoutes()
	stub.body = want

	sock, _ := startTestServerWithRoutes(t, &stubStatus{data: []byte(`{}`)}, &stubPool{}, stub)

	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "rpc",
		Method:       "routes",
		Server:       "srv1",
	})
	if resp.Status != 0 {
		t.Fatalf("routes rpc failed: status=%d msg=%q", resp.Status, resp.Msg)
	}
	if string(resp.Body) != string(want) {
		t.Errorf("body = %s, want %s", resp.Body, want)
	}

	select {
	case got := <-stub.calls:
		if got != "srv1" {
			t.Errorf("provider saw server = %q, want %q", got, "srv1")
		}
	default:
		t.Fatal("RoutesJSON was never called")
	}
}

// TestRPCRoutes_MissingServerField proves an empty server name is rejected
// before the provider is ever consulted — the provider doesn't get to
// invent a meaning for "no server named".
func TestRPCRoutes_MissingServerField(t *testing.T) {
	stub := newStubRoutes()
	stub.body = []byte(`{}`)
	sock, _ := startTestServerWithRoutes(t, &stubStatus{data: []byte(`{}`)}, &stubPool{}, stub)

	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "rpc",
		Method:       "routes",
	})
	if resp.Status == 0 {
		t.Fatal("expected non-zero status for a routes request with no server name")
	}
	select {
	case <-stub.calls:
		t.Fatal("RoutesJSON was called despite a missing server name")
	default:
	}
}

// TestRPCRoutes_NoProviderConfigured proves a daemon that never called
// SetRoutes refuses the method cleanly instead of a nil-pointer panic —
// the same shape TestRPCDoctor_NoProviderConfigured already proves for
// "doctor" (see the doctor case in handleRPC).
func TestRPCRoutes_NoProviderConfigured(t *testing.T) {
	sock := startTestServer(t, &stubStatus{data: []byte(`{}`)}, &stubPool{})

	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "rpc",
		Method:       "routes",
		Server:       "srv1",
	})
	if resp.Status == 0 {
		t.Fatal("expected non-zero status when no RoutesProvider is configured")
	}
}

// TestRPCRoutes_ProviderRoutesError_RelaysStatusAndMsg proves a *RoutesError
// from the provider is relayed to the caller verbatim — the exact status and
// message the provider chose, not a generic re-wording. This is what lets
// the state-table's distinct messages (internal/daemon's routesProvider)
// actually reach an IPC caller unchanged.
func TestRPCRoutes_ProviderRoutesError_RelaysStatusAndMsg(t *testing.T) {
	stub := newStubRoutes()
	stub.err = &ipc.RoutesError{Status: 3, Msg: `server "srv1" is disabled; set enabled = true in the config to use it`}
	sock, _ := startTestServerWithRoutes(t, &stubStatus{data: []byte(`{}`)}, &stubPool{}, stub)

	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "rpc",
		Method:       "routes",
		Server:       "srv1",
	})
	if resp.Status != 3 {
		t.Errorf("Status = %d, want 3", resp.Status)
	}
	want := `server "srv1" is disabled; set enabled = true in the config to use it`
	if resp.Msg != want {
		t.Errorf("Msg = %q, want %q", resp.Msg, want)
	}
}

// TestRPCRoutes_ProviderGenericError_Masked proves an error from the
// provider that is NOT a *RoutesError — an unexpected local failure, not one
// of the taxonomy's named states — is masked with a generic message rather
// than leaking implementation detail to the caller, matching how "doctor"
// and "status" already mask their own unexpected provider errors.
func TestRPCRoutes_ProviderGenericError_Masked(t *testing.T) {
	stub := newStubRoutes()
	stub.err = errors.New("boom: some unrelated internal failure")
	sock, _ := startTestServerWithRoutes(t, &stubStatus{data: []byte(`{}`)}, &stubPool{}, stub)

	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "rpc",
		Method:       "routes",
		Server:       "srv1",
	})
	if resp.Status == 0 {
		t.Fatal("expected non-zero status for a masked provider error")
	}
	if resp.Msg == "boom: some unrelated internal failure" {
		t.Error("the provider's raw internal error text reached the caller unmasked")
	}
}

// TestRPCRoutes_OversizedBody_ReturnsCleanError proves a route-table JSON
// body large enough to blow the IPC frame cap once wrapped in its CBOR
// envelope is rejected with a named, non-zero-status error response —
// instead of the write silently failing inside writeFrame and leaving the
// caller with nothing but a closed connection and no response frame at
// all.
func TestRPCRoutes_OversizedBody_ReturnsCleanError(t *testing.T) {
	stub := newStubRoutes()
	stub.body = bytes.Repeat([]byte("a"), 64*1024) // exceeds the frame cap once enveloped
	sock, _ := startTestServerWithRoutes(t, &stubStatus{data: []byte(`{}`)}, &stubPool{}, stub)

	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "rpc",
		Method:       "routes",
		Server:       "srv1",
	})
	if resp.Status == 0 {
		t.Fatal("expected a non-zero status for an oversized route table")
	}
	if resp.Body != nil {
		t.Errorf("expected no body on the error response, got %d bytes", len(resp.Body))
	}
	if resp.Msg == "" {
		t.Error("expected a non-empty message explaining the size limit")
	}
}

// startTestServerWithRoutes is startTestServer plus SetRoutes, since
// SetRoutes must be called before Serve starts accepting and no existing
// helper in this file threads a RoutesProvider through.
func startTestServerWithRoutes(t *testing.T, status ipc.StatusProvider, pool ipc.AttachPool, routes ipc.RoutesProvider) (string, *ipc.Server) {
	t.Helper()
	sock := shortSocketPath(t)
	srv := ipc.NewServer(sock, status, pool)
	srv.SetRoutes(routes)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return sock, srv
}
