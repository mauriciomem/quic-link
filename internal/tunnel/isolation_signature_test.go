package tunnel

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// handlersThatMustNotHoldTheRouteTable are the functions that run per stream,
// on behalf of whoever opened it. None of them may hold the concrete route
// table: holding it is what would make a mutator reachable from the path that
// only needs to forward traffic.
var handlersThatMustNotHoldTheRouteTable = map[string]bool{
	"serveStream":  true,
	"serveControl": true,
}

// TestStreamHandlersDoNotHoldTheConcreteRouteTable reads this package's own
// source and asserts the per-stream handlers take a narrowed handle rather than
// the route table itself.
//
// It is written against the syntax rather than the behaviour because the
// property being protected is structural: a handler that cannot name a mutator
// cannot call one, now or after some later edit. A test that exercised the
// handlers could only show that today's code does not mutate anything, which is
// a much weaker statement and one that a future change could quietly falsify
// while still passing.
//
// The companion assertion on the interface's method set lives beside this one;
// together they cover both halves — that the handlers take the narrow type, and
// that the narrow type stays narrow.
func TestStreamHandlersDoNotHoldTheConcreteRouteTable(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parse this package: %v", err)
	}

	checked := map[string]bool{}
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Type.Params == nil {
					continue
				}
				if !handlersThatMustNotHoldTheRouteTable[fn.Name.Name] {
					continue
				}
				checked[fn.Name.Name] = true
				for _, param := range fn.Type.Params.List {
					star, ok := param.Type.(*ast.StarExpr)
					if !ok {
						continue
					}
					sel, ok := star.X.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					ident, ok := sel.X.(*ast.Ident)
					if !ok {
						continue
					}
					if ident.Name == "router" && sel.Sel.Name == "Router" {
						t.Errorf("%s takes the concrete route table; a per-stream handler must "+
							"take a handle narrowed to what forwarding needs, or a route-table "+
							"mutator becomes reachable from the data path", fn.Name.Name)
					}
				}
			}
		}
	}

	// A renamed or deleted handler must not silently pass by being absent.
	for name := range handlersThatMustNotHoldTheRouteTable {
		if !checked[name] {
			t.Errorf("%s was not found in this package; if it was renamed, update the list so "+
				"this assertion keeps covering it", name)
		}
	}
}
