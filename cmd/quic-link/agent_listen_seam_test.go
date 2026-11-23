/**
 * @spec-handoff
 * @interface identity.ListenTLSWithPairingConfig(steady func() (*tls.Config, error), pairing *tls.Config, pairingOpen func() bool) (*tls.Config, error)  // exported, unwired
 * @interface agentListenTransport(conn net.PacketConn, tlsConf *tls.Config) (*transport.QUICTransport, error)  // unchanged
 * @behavior
 *   - real loopback QUIC through agentListenTransport: steady offer negotiates quic-link/1, open-window pair1 offer negotiates quic-link/pair1
 *   - no branch ever issues a session ticket; a second dial never resumes (control: a tickets-enabled listener DOES issue one)
 *   - pair1 with the window closed fails like a version mismatch (TransportError 0x178)
 *   - a failing steady source fails closed as an auth failure (transport.IsAuthFailed)
 *   - guard: AgentListenTLS / ClientListenTLS listeners advertise only quic-link/1
 *   - guard: no non-test .go file in the module outside internal/identity and internal/pairing references
 *     ListenTLSWithPairingConfig, imports internal/pairing, or spells "quic-link/pair1" (also as a constant concatenation);
 *     the one exemption is the plain literal value of the top-level const ALPNPair in internal/transport itself, and the name
 *     ALPNPair is a violation outside internal/identity and internal/pairing except as that declaring identifier
 *     (an alias, a use or a function-local const in internal/transport, or any use in a transport subpackage, is flagged)
 * @edge-cases
 *   - ticket storage is post-handshake and async: positive checks wait on a Put signal, negative checks wait a bounded window
 * @see ../../internal/identity/tls.go
 */
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/transport"
)

const seamPair1 = "quic-link/pair1"

func seamUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func newSeamKeys(t *testing.T) (srv, cli ed25519.PrivateKey, srvPin, cliPin string) {
	t.Helper()
	gen := func() ed25519.PrivateKey {
		k, err := identity.Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		return k
	}
	pin := func(k ed25519.PrivateKey) string {
		p, err := identity.PinForKey(k)
		if err != nil {
			t.Fatalf("PinForKey: %v", err)
		}
		return p
	}
	srv, cli = gen(), gen()
	return srv, cli, pin(srv), pin(cli)
}

// seamServe starts a listener on agentListenTransport and accepts in the
// background, keeping accepted connections open (a ticket is delivered
// post-handshake) until cleanup.
func seamServe(t *testing.T, tlsConf *tls.Config) net.Addr {
	t.Helper()
	conn := seamUDP(t)
	tr, err := agentListenTransport(conn, tlsConf)
	if err != nil {
		t.Fatalf("agentListenTransport: %v", err)
	}
	ln, err := tr.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var held []transport.Conn
		defer func() {
			for _, c := range held {
				c.CloseWithError(0, "")
			}
		}()
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		tr.Close()
		wg.Wait()
	})
	return conn.LocalAddr()
}

type seamPutCache struct {
	tls.ClientSessionCache
	putc chan struct{}
}

func (c *seamPutCache) Put(k string, cs *tls.ClientSessionState) {
	c.ClientSessionCache.Put(k, cs)
	select {
	case c.putc <- struct{}{}:
	default:
	}
}

// seamClient is a raw quic-go client, the way a hostile or pairing peer
// would be: own cache, tickets accepted, chosen ALPN offer.
type seamClient struct {
	tr   *quic.Transport
	conf *tls.Config
	putc chan struct{}
}

func newSeamClient(t *testing.T, cliKey ed25519.PrivateKey, srvPin string, protos ...string) *seamClient {
	t.Helper()
	base, err := identity.ClientDialTLS(cliKey, srvPin)
	if err != nil {
		t.Fatalf("ClientDialTLS: %v", err)
	}
	conf := base.Clone()
	conf.NextProtos = protos
	conf.SessionTicketsDisabled = false
	putc := make(chan struct{}, 1)
	conf.ClientSessionCache = &seamPutCache{ClientSessionCache: tls.NewLRUClientSessionCache(4), putc: putc}
	tr := &quic.Transport{Conn: seamUDP(t)}
	t.Cleanup(func() { tr.Close() })
	return &seamClient{tr: tr, conf: conf, putc: putc}
}

func (c *seamClient) dial(t *testing.T, addr net.Addr) (*quic.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.tr.Dial(ctx, addr, c.conf, nil)
	if err == nil {
		t.Cleanup(func() { conn.CloseWithError(0, "") })
	}
	return conn, err
}

func (c *seamClient) sawTicket(wait time.Duration) bool {
	select {
	case <-c.putc:
		return true
	case <-time.After(wait):
		return false
	}
}

func wantTransportCode(t *testing.T, err error, code quic.TransportErrorCode) {
	t.Helper()
	var te *quic.TransportError
	if !errors.As(err, &te) || te.ErrorCode != code {
		t.Fatalf("dial err = %v, want TransportError 0x%x", err, uint64(code))
	}
}

// TestAgentListenTransport_PairingSeamHandshake - ticket suppression and
// ALPN routing over a real handshake through the agent's listening transport helper.
func TestAgentListenTransport_PairingSeamHandshake(t *testing.T) {
	srvKey, cliKey, srvPin, cliPin := newSeamKeys(t)
	steady, err := identity.AgentListenTLS(srvKey, []string{cliPin})
	if err != nil {
		t.Fatalf("AgentListenTLS: %v", err)
	}
	pairing := steady.Clone()
	pairing.NextProtos = []string{seamPair1}
	steadySrc := func() (*tls.Config, error) { return steady, nil }
	seam := func(t *testing.T, src func() (*tls.Config, error), open bool) net.Addr {
		t.Helper()
		outer, err := identity.ListenTLSWithPairingConfig(src, pairing, func() bool { return open })
		if err != nil {
			t.Fatalf("ListenTLSWithPairingConfig: %v", err)
		}
		return seamServe(t, outer)
	}

	t.Run("control: tickets-enabled listener is observed issuing a ticket", func(t *testing.T) {
		leaky := steady.Clone()
		leaky.SessionTicketsDisabled = false
		addr := seamServe(t, leaky)
		cli := newSeamClient(t, cliKey, srvPin, transport.ALPN)
		if _, err := cli.dial(t, addr); err != nil {
			t.Fatalf("dial: %v", err)
		}
		if !cli.sawTicket(5 * time.Second) {
			t.Fatal("no ticket observed from a tickets-enabled listener: the ticket check below is blind")
		}
	})

	for _, tc := range []struct {
		name, offer, want string
		open              bool
	}{
		{"steady branch", transport.ALPN, transport.ALPN, false},
		{"pairing branch, window open", seamPair1, seamPair1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := seam(t, steadySrc, tc.open)
			cli := newSeamClient(t, cliKey, srvPin, tc.offer)
			for i := range 2 {
				conn, err := cli.dial(t, addr)
				if err != nil {
					t.Fatalf("dial %d: %v", i, err)
				}
				cs := conn.ConnectionState().TLS
				if cs.NegotiatedProtocol != tc.want {
					t.Errorf("dial %d: NegotiatedProtocol = %q, want %q", i, cs.NegotiatedProtocol, tc.want)
				}
				if cs.DidResume {
					t.Errorf("dial %d resumed: the pin check was skipped", i)
				}
			}
			if cli.sawTicket(500 * time.Millisecond) {
				t.Error("listener issued a session ticket through the seam")
			}
		})
	}

	t.Run("pair1 with window closed fails like a version mismatch", func(t *testing.T) {
		addr := seam(t, steadySrc, false)
		_, err := newSeamClient(t, cliKey, srvPin, seamPair1).dial(t, addr)
		wantTransportCode(t, err, 0x178)
	})

	t.Run("steady source error fails closed as auth failure", func(t *testing.T) {
		addr := seam(t, func() (*tls.Config, error) { return nil, errors.New("source down") }, false)
		_, err := newSeamClient(t, cliKey, srvPin, transport.ALPN).dial(t, addr)
		if err == nil || !transport.IsAuthFailed(err) {
			t.Fatalf("dial err = %v, want an auth failure (exit 4)", err)
		}
	})
}

// TestAgentAndDaemon_AdvertiseOnlyQuicLink1 is a regression guard: the
// production listeners never accept pair1, and nothing outside identity
// wires the seam in.
func TestAgentAndDaemon_AdvertiseOnlyQuicLink1(t *testing.T) {
	srvKey, cliKey, srvPin, cliPin := newSeamKeys(t)
	agentConf, err := identity.AgentListenTLS(srvKey, []string{cliPin})
	if err != nil {
		t.Fatalf("AgentListenTLS: %v", err)
	}
	daemonConf, err := identity.ClientListenTLS(srvKey, cliPin)
	if err != nil {
		t.Fatalf("ClientListenTLS: %v", err)
	}
	for name, conf := range map[string]*tls.Config{"agent (agent.go)": agentConf, "daemon (daemoncmd.go)": daemonConf} {
		t.Run(name, func(t *testing.T) {
			if len(conf.NextProtos) != 1 || conf.NextProtos[0] != transport.ALPN {
				t.Errorf("NextProtos = %q, want exactly [%q]", conf.NextProtos, transport.ALPN)
			}
			addr := seamServe(t, conf)
			_, err := newSeamClient(t, cliKey, srvPin, seamPair1).dial(t, addr)
			wantTransportCode(t, err, 0x178)
		})
	}

	t.Run("no production reference to the seam", func(t *testing.T) {
		root := seamModuleRoot(t)
		modPath := seamModulePath(t, root)
		pairingImport := modPath + "/internal/pairing"
		skip := map[string]bool{
			filepath.Join(root, "internal", "identity"): true,
			filepath.Join(root, "internal", "pairing"):  true,
		}
		var scan seamScan
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				name := d.Name()
				if path != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || skip[path]) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				return err
			}
			for _, v := range seamScanFile(fset, f, filepath.ToSlash(rel), pairingImport, &scan) {
				t.Error(v)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", root, err)
		}
		if !scan.sawAgentListenTLS {
			t.Fatal("scan never saw AgentListenTLS: the scanner is blind")
		}
		if !scan.sawALPNPairDecl {
			t.Fatal("scan never saw const ALPNPair in internal/transport: the exemption anchor is gone")
		}
	})

	t.Run("scanner applies the ALPNPair rules", func(t *testing.T) {
		const imp = "github.com/mauriciomem/quic-link/internal/pairing"
		for _, tc := range []struct {
			name, dir, src string
			violations     int
			decl           bool
		}{
			{"exempt: the ALPNPair constant in internal/transport", "internal/transport",
				`package transport; const ALPNPair = "quic-link/pair1"`, 0, true},
			{"exempt: grouped const", "internal/transport",
				"package transport\nconst (\n\tALPN = \"quic-link/1\"\n\tALPNPair = \"quic-link/pair1\"\n)", 0, true},
			{"name allowed in internal/pairing", "internal/pairing",
				`package pairing; import "x/internal/transport"; var _ = transport.ALPNPair`, 0, false},
			{"name allowed in internal/identity", "internal/identity",
				`package identity; import "x/internal/transport"; const alpnPair1 = transport.ALPNPair`, 0, false},
			{"flagged: transport/mem names ALPNPair", "internal/transport/mem",
				`package mem; import "x/internal/transport"; var _ = transport.ALPNPair`, 1, false},
			{"flagged: transport.ALPNPair referenced from cmd", "cmd/quic-link",
				`package main; import "x/internal/transport"; var _ = transport.ALPNPair`, 1, false},
			{"flagged: ALPNPair declared outside transport", "internal/daemon",
				`package daemon; const ALPNPair = "quic-link/pair1"`, 2, false},
			{"flagged: literal under another constant name", "internal/transport",
				`package transport; const Other = "quic-link/pair1"`, 1, false},
			{"flagged: ALPNPair as a var", "internal/transport",
				`package transport; var ALPNPair = "quic-link/pair1"`, 2, false},
			{"flagged: ALPNPair built by concatenation", "internal/transport",
				`package transport; const ALPNPair = "quic-link/" + "pair1"`, 1, true},
			{"flagged: ALPNPair parenthesized", "internal/transport",
				`package transport; const ALPNPair = ("quic-link/pair1")`, 1, true},
			{"flagged: literal in transport subpackage", "internal/transport/mem",
				`package mem; const ALPNPair = "quic-link/pair1"`, 2, false},
			{"flagged: second name of the same spec", "internal/transport",
				`package transport; const ALPNPair, B = "quic-link/pair1", "quic-link/pair1"`, 1, true},
			{"flagged: literal elsewhere in transport", "internal/transport",
				`package transport; const ALPNPair = "quic-link/pair1"; func f() string { return "quic-link/pair1" }`, 1, true},
			{"flagged: alias of ALPNPair in transport", "internal/transport",
				`package transport; const ALPNPair = "quic-link/pair1"; const PairProto = ALPNPair`, 1, true},
			{"flagged: ALPNPair returned by a transport function", "internal/transport",
				`package transport; const ALPNPair = "quic-link/pair1"; func PairProtos() []string { return []string{ALPNPair} }`, 1, true},
			{"flagged: function-local ALPNPair const in transport", "internal/transport",
				`package transport; func f() string { const ALPNPair = "quic-link/pair1"; return ALPNPair }`, 3, false},
			{"flagged: pairing import", "internal/daemon",
				`package daemon; import _ "` + imp + `"`, 1, false},
			{"flagged: seam constructor", "internal/daemon",
				`package daemon; var _ = identity.ListenTLSWithPairingConfig`, 1, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fset := token.NewFileSet()
				f, err := parser.ParseFile(fset, "synthetic.go", tc.src, 0)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				var scan seamScan
				v := seamScanFile(fset, f, tc.dir, imp, &scan)
				if len(v) != tc.violations {
					t.Errorf("violations = %d %q, want %d", len(v), v, tc.violations)
				}
				if scan.sawALPNPairDecl != tc.decl {
					t.Errorf("sawALPNPairDecl = %v, want %v", scan.sawALPNPairDecl, tc.decl)
				}
			})
		}
	})

	t.Run("scanner folds string concatenation", func(t *testing.T) {
		for _, src := range []string{`"quic-link/" + "pair1"`, `("quic-" + "link/") + ("pa" + "ir1")`, "`quic-link/pair1`"} {
			e, err := parser.ParseExpr(src)
			if err != nil {
				t.Fatalf("parse %s: %v", src, err)
			}
			if v, ok := seamConstString(e); !ok || v != seamPair1 {
				t.Errorf("%s folded to %q, %v", src, v, ok)
			}
		}
	})
}

// seamConstString folds a string-literal expression (literals joined by +,
// possibly parenthesized) to its value.
func seamConstString(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(x.Value)
		return v, err == nil
	case *ast.ParenExpr:
		return seamConstString(x.X)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, ok := seamConstString(x.X)
		if !ok {
			return "", false
		}
		r, ok := seamConstString(x.Y)
		return l + r, ok
	}
	return "", false
}

// seamScan collects the anchors a full scan must see.
type seamScan struct {
	sawAgentListenTLS bool // the scanner reads production identifiers at all
	sawALPNPairDecl   bool // the exempt ALPNPair constant exists where the exemption allows it
}

// seamAllowsALPNPairName reports whether production code in dir (module-relative,
// slash-separated) may name ALPNPair: the pairing-capable packages only.
func seamAllowsALPNPairName(dir string) bool {
	for _, p := range []string{"internal/identity", "internal/pairing", "internal/transport"} {
		if dir == p || strings.HasPrefix(dir, p+"/") {
			return true
		}
	}
	return false
}

// seamScanFile returns one message per seam violation in a production file in
// dir (module-relative, slash-separated). The "quic-link/pair1" literal is
// exempt only as the plain value of a const named ALPNPair in
// internal/transport itself; the name ALPNPair is a violation outside the
// pairing-capable packages.
func seamScanFile(fset *token.FileSet, f *ast.File, dir, pairingImport string, scan *seamScan) []string {
	var out []string
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == pairingImport || strings.HasPrefix(p, pairingImport+"/") {
			out = append(out, fmt.Sprintf("%s: production code imports %s", fset.Position(imp.Pos()), p))
		}
	}
	exempt := map[*ast.BasicLit]bool{}
	allowName := seamAllowsALPNPairName(dir)
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GenDecl:
			if x.Tok != token.CONST || dir != "internal/transport" {
				break
			}
			for _, spec := range x.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if name.Name != "ALPNPair" {
						continue
					}
					scan.sawALPNPairDecl = true
					if i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
							if v, ok := seamConstString(lit); ok && v == seamPair1 {
								exempt[lit] = true
							}
						}
					}
				}
			}
		case *ast.Ident:
			if x.Name == "ListenTLSWithPairingConfig" {
				out = append(out, fmt.Sprintf("%s: production code references ListenTLSWithPairingConfig", fset.Position(x.Pos())))
			}
			if x.Name == "AgentListenTLS" {
				scan.sawAgentListenTLS = true
			}
			if x.Name == "ALPNPair" && !allowName {
				out = append(out, fmt.Sprintf("%s: production code outside identity, pairing and transport names ALPNPair", fset.Position(x.Pos())))
			}
		case *ast.BinaryExpr:
			if v, ok := seamConstString(x); ok && strings.Contains(v, seamPair1) {
				out = append(out, fmt.Sprintf("%s: production code builds %q", fset.Position(x.Pos()), v))
				return false
			}
		case *ast.BasicLit:
			if v, ok := seamConstString(x); ok && strings.Contains(v, seamPair1) && !exempt[x] {
				out = append(out, fmt.Sprintf("%s: production code contains %q", fset.Position(x.Pos()), v))
			}
		}
		return true
	})
	return out
}

// seamModuleRoot finds the directory holding go.mod, walking up from the
// package directory.
func seamModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the package directory")
		}
		dir = parent
	}
}

func seamModulePath(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	t.Fatal("go.mod has no module line")
	return ""
}
