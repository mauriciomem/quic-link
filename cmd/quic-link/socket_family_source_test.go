package main

// socket_family_source_test.go attests, from the source itself, which address
// family each UDP socket in this package is bound in.
//
// Three of the sockets here cannot be reached from a test: they are bound
// inside a function that immediately goes on to use them and never hands them
// back, and reaching them would mean a live peer on the other end. Their family
// is still a decision worth guarding, so it is guarded the only way left — by
// reading the source and comparing every bind against a recorded expectation.
//
// This follows the same reasoning used elsewhere in this package for rules that
// cannot be observed at run time: a behavioural test catches a change only on
// the platform it was made on, while a source attestation catches it in review,
// on every platform. The two socket-family tests that can run do run; this
// covers the rest.
//
// What this does not catch: a network string assembled at run time instead of
// written as a literal. That case is reported as a failure rather than skipped,
// so it cannot pass unnoticed.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// expectedSocketFamilies records, per function, the network string of every UDP
// socket it binds, in source order, and why that family is the right one.
//
// A function binding more than one socket lists them all: a function that opens
// one socket per address family legitimately holds both, and recording them in
// order is what makes swapping them visible.
var expectedSocketFamilies = map[string]struct {
	networks []string
	reason   string
}{
	"agentRun": {
		networks: []string{"udp"},
		reason:   "waits for connections, so it must be reachable over either family",
	},
	"bindDialingSocket": {
		networks: []string{"udp6", "udp4"},
		reason:   "opens the socket every outgoing connection uses, one family per socket, chosen from the address being dialled; a socket carrying both families fails silently against on-link IPv4 peers on some platforms",
	},
	"bindServerSocket": {
		networks: []string{"udp"},
		reason:   "waits for a connection, so it must be reachable over either family; the direction that connects out is opened by the shared helper instead",
	},
	"acquireNamingListeners": {
		networks: []string{"udp4"},
		reason:   "answers name queries on the loopback only, where the family is fixed for unrelated reasons",
	},
}

// TestEveryUDPSocketBindsTheRecordedFamily walks this package's source, finds
// every UDP bind, and compares it against the recorded expectation.
func TestEveryUDPSocketBindsTheRecordedFamily(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("cannot read this package's source: %v", err)
	}

	found := map[string][]string{}
	where := map[string][]string{}

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			// Track the innermost enclosing function declaration so a bind can
			// be attributed by name rather than by line number, which drifts.
			var current string
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.FuncDecl:
					current = node.Name.Name
				case *ast.CallExpr:
					sel, ok := node.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkgIdent, ok := sel.X.(*ast.Ident)
					if !ok || pkgIdent.Name != "net" {
						return true
					}
					if sel.Sel.Name != "ListenUDP" && sel.Sel.Name != "ListenPacket" {
						return true
					}
					if len(node.Args) == 0 {
						return true
					}
					pos := fset.Position(node.Pos())
					lit, ok := node.Args[0].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Errorf("%s (%s:%d) binds a UDP socket with a network string that is not "+
							"written literally; the family can no longer be attested from the source, "+
							"so either write it literally or assert the family at run time",
							current, pos.Filename, pos.Line)
						return true
					}
					network, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Errorf("%s (%s:%d): cannot read the network string %s",
							current, pos.Filename, pos.Line, lit.Value)
						return true
					}
					if !strings.HasPrefix(network, "udp") {
						return true
					}
					found[current] = append(found[current], network)
					where[current] = append(where[current],
						pos.Filename+":"+strconv.Itoa(pos.Line))
				}
				return true
			})
		}
	}

	if len(found) == 0 {
		t.Fatal("no UDP socket binds found in this package's source; this test needs the " +
			"source tree beside it and cannot attest anything without it")
	}

	for name, got := range found {
		want, recorded := expectedSocketFamilies[name]
		if !recorded {
			t.Errorf("%s (%s) binds a UDP socket but is not recorded here. A new socket is a "+
				"decision: record which family it uses and why, so the next person changing it "+
				"can see what it was for", name, strings.Join(where[name], ", "))
			continue
		}
		if !equalStrings(got, want.networks) {
			t.Errorf("%s (%s) binds %v, want %v, because it %s",
				name, strings.Join(where[name], ", "), got, want.networks, want.reason)
		}
	}

	// A recorded function that no longer binds anything is just as interesting:
	// it means the bind moved or the function was renamed, and the expectation
	// above is now guarding nothing.
	var missing []string
	for name := range expectedSocketFamilies {
		if _, ok := found[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("%s no longer binds a UDP socket. If it was renamed or the bind moved, "+
			"update the recorded set so this stays a real check rather than a stale one", name)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
