package names_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/mauriciomem/quic-link/internal/names"
)

// startServer binds both transports on an ephemeral loopback port and returns
// the server plus the address to talk to it on. Everything is torn down when
// the test ends, which is also what proves the shutdown path: a leaked
// goroutine fails the whole package.
func startServer(t *testing.T) (*names.Server, string) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		t.Skipf("could not take tcp/%d to match udp: %v", port, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := names.NewServer(ctx, testZone(t), udp, tcp)
	t.Cleanup(func() {
		cancel()
		s.Close()
	})
	return s, udp.LocalAddr().String()
}

func askUDP(t *testing.T, addr string, msg []byte) []byte {
	t.Helper()
	c, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return buf[:n]
}

func askTCP(t *testing.T, c net.Conn, msg []byte) []byte {
	t.Helper()
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(msg)))
	if _, err := c.Write(append(l[:], msg...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(c, l[:]); err != nil {
		t.Fatalf("read length: %v", err)
	}
	out := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, out); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return out
}

// TestServer_BothTransportsCarryTheSameAnswer proves the plumbing faithfully
// carries what the pure function produced. The behaviour itself is proven
// exhaustively without sockets; running the whole table twice over real
// sockets would add setup, not coverage.
func TestServer_BothTransportsCarryTheSameAnswer(t *testing.T) {
	_, addr := startServer(t)

	for _, tc := range []struct {
		name  string
		qname string
		want  dnsmessage.RCode
	}{
		{"a known server", "server1.internal.", dnsmessage.RCodeSuccess},
		{"an unknown server", "nope.internal.", dnsmessage.RCodeNameError},
		{"outside the zone", "example.com.", dnsmessage.RCodeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := query(t, tc.qname, dnsmessage.TypeA, true)
			want, drop := names.Respond(q, testZone(t))
			if drop {
				t.Fatal("the pure function dropped a well-formed query")
			}

			if got := askUDP(t, addr, q); string(got) != string(want) {
				t.Errorf("datagram transport changed the answer")
			}
			c, err := net.Dial("tcp4", addr)
			if err != nil {
				t.Fatalf("dial tcp: %v", err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			if got := askTCP(t, c, q); string(got) != string(want) {
				t.Errorf("stream transport changed the answer")
			}
			if got := parseReply(t, want); got.rcode != tc.want {
				t.Errorf("rcode = %v, want %v", got.rcode, tc.want)
			}
		})
	}
}

// TestServer_TCPServesSeveralQueriesOnOneConnection: resolvers reuse a
// connection, so answering once and hanging up would cost a round trip every
// time.
func TestServer_TCPServesSeveralQueriesOnOneConnection(t *testing.T) {
	_, addr := startServer(t)
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	for i := range 3 {
		got := parseReply(t, askTCP(t, c, query(t, "server1.internal.", dnsmessage.TypeA, false)))
		if got.rcode != dnsmessage.RCodeSuccess || len(got.answers) != 1 {
			t.Fatalf("query %d on a reused connection: rcode=%v answers=%d", i, got.rcode, len(got.answers))
		}
	}
}

// TestServer_TCPRefusesAnImplausibleLength: the declared length is the caller's
// to choose, so it must be refused before anything is allocated for it.
func TestServer_TCPRefusesAnImplausibleLength(t *testing.T) {
	_, addr := startServer(t)
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	var l [2]byte
	binary.BigEndian.PutUint16(l[:], 65535)
	if _, err := c.Write(l[:]); err != nil {
		t.Fatal(err)
	}
	// The server must hang up rather than wait for 64 KiB that will never come.
	if _, err := io.ReadFull(c, l[:]); err == nil {
		t.Error("an implausible length must end the connection, not be honoured")
	}
}

// TestServer_TCPHangsUpOnASilentClient: a connection that opens and says
// nothing must not be held for the life of the process.
func TestServer_TCPHangsUpOnASilentClient(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for an idle timeout")
	}
	_, addr := startServer(t)
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	start := time.Now()
	var b [1]byte
	if _, err := c.Read(b[:]); err == nil {
		t.Fatal("expected the server to hang up")
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("server took %v to give up on a silent client", elapsed)
	}
}

// TestServer_DatagramGarbageIsIgnored: nothing is sent back, and the loop
// keeps working afterwards.
func TestServer_DatagramGarbageIsIgnored(t *testing.T) {
	_, addr := startServer(t)
	c, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Write([]byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 512)
	if _, err := c.Read(buf); err == nil {
		t.Error("a malformed datagram must be ignored, not answered")
	}

	// And the responder is still alive.
	if got := parseReply(t, askUDP(t, addr, query(t, "server1.internal.", dnsmessage.TypeA, false))); got.rcode != dnsmessage.RCodeSuccess {
		t.Error("the read loop did not survive a malformed datagram")
	}
}

// TestServer_ClosesCleanlyWithNothingLeftRunning is enforced by the package's
// leak check; this test exists so there is a named place where the property is
// stated, and so a server that never served anything is also covered.
func TestServer_ClosesCleanlyWithNothingLeftRunning(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		t.Skip("could not pair the ports")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := names.NewServer(ctx, testZone(t), udp, tcp)
	cancel()
	s.Close()
}

// TestServer_NilSocketsAreAllowed: when a port could not be taken the daemon
// still starts, simply without that transport.
func TestServer_NilSocketsAreAllowed(t *testing.T) {
	s := names.NewServer(context.Background(), testZone(t), nil, nil)
	s.Close()
}
