package control

import (
	"net"
	"sync"
)

// singleConnListener is a net.Listener that yields exactly one pre-supplied
// net.Conn from Accept, then blocks until Close. It lets a standard
// *grpc.Server serve a single already-accepted control stream: Serve() calls
// Accept once, receives our conn, and never busy-spins because the second
// Accept blocks until Close returns net.ErrClosed.
type singleConnListener struct {
	conn net.Conn

	mu     sync.Mutex
	handed bool

	closed    chan struct{}
	closeOnce sync.Once
}

// NewSingleConnListener wraps one conn as a net.Listener.
func NewSingleConnListener(conn net.Conn) net.Listener {
	return &singleConnListener{
		conn:   conn,
		closed: make(chan struct{}),
	}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.handed {
		l.handed = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	// The single conn was already handed out; block until Close.
	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return controlAddr{} }
