package names_test

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/names"
)

// realClientHello captures the exact first flight a real TLS client sends,
// including the extensions and random padding no hand-written fixture imitates.
func realClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 8192)
		_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := server.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
		server.Close()
	}()
	go func() {
		c := tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		_ = c.Handshake()
		client.Close()
	}()
	select {
	case b := <-got:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("no client hello captured")
		return nil
	}
}

func TestSNI_FromARealClient(t *testing.T) {
	for _, name := range []string{"grafana.server1.internal", "a.b.server1.internal", "server1.internal"} {
		hello := realClientHello(t, name)
		host, need, err := names.SNIFromClientHello(hello)
		if err != nil || need {
			t.Fatalf("%s: err=%v need=%v", name, err, need)
		}
		if host != name {
			t.Errorf("host = %q, want %q", host, name)
		}
	}
}

// TestSNI_AsksForMoreWhenTheHelloIsIncomplete: a handshake may arrive in
// pieces, and giving up on the first piece would refuse ordinary clients.
func TestSNI_AsksForMoreWhenTheHelloIsIncomplete(t *testing.T) {
	hello := realClientHello(t, "grafana.server1.internal")
	for _, cut := range []int{1, 4, 5, 10, len(hello) / 2, len(hello) - 1} {
		host, need, err := names.SNIFromClientHello(hello[:cut])
		if err != nil {
			t.Errorf("cut at %d: unexpected error %v", cut, err)
		}
		if !need {
			t.Errorf("cut at %d: should ask for more, got host %q", cut, host)
		}
	}
}

func TestSNI_RefusesWhatIsNotAHandshake(t *testing.T) {
	cases := map[string][]byte{
		"plain http":        []byte("GET / HTTP/1.1\r\nHost: a.internal\r\n\r\n"),
		"wrong record type": {0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5},
		"absurd length":     {0x16, 0x03, 0x01, 0xff, 0xff},
		"zero length":       {0x16, 0x03, 0x01, 0x00, 0x00},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, need, err := names.SNIFromClientHello(in); err == nil && !need {
				t.Error("must be refused")
			} else if need && name != "absurd length" {
				// Asking for more on a bad record type would be wrong.
				if name == "wrong record type" || name == "plain http" || name == "zero length" {
					t.Errorf("must be refused outright, not waited on")
				}
			}
		})
	}
}

// TestSNI_RefusesAHandshakeWithNoName: without a name there is nothing to route
// on, and guessing a default would send a connection somewhere nobody asked for.
func TestSNI_RefusesAHandshakeWithNoName(t *testing.T) {
	hello := realClientHello(t, "")
	_, need, err := names.SNIFromClientHello(hello)
	if need {
		t.Fatal("a complete hello must not ask for more")
	}
	if !errors.Is(err, names.ErrNoSNI) && err == nil {
		t.Errorf("a hello with no name must be refused, got err=%v", err)
	}
}

func FuzzSNIFromClientHello(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		host, need, err := names.SNIFromClientHello(in)
		if err == nil && !need && host == "" {
			t.Fatal("a success must name a host")
		}
	})
}
