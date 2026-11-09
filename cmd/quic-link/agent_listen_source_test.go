package main

// agent_listen_source_test.go attests, from the source itself, that the agent
// accepts connections through the transport that validates the source address
// of new clients, rather than through a transport built some other way.
//
// The agent's listening transport is built by agentListenTransport, and a
// behavioural test exercises that helper directly. That test cannot notice the
// agent's run loop being changed to build its own transport and skip the helper:
// the helper would still behave, and simply no longer be used. The wiring is
// only visible in the source, so it is checked there.
//
// What this does not catch: the listening transport being built in some other
// function that agentRun calls. The check reads the body of agentRun only, which
// is where the transport is built today.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// callsIn returns every call in body written as pkg.Func(...) or as a bare
// Func(...), keyed by the call as written, e.g. "transport.NewQUICTransport"
// or "agentListenTransport".
func callsIn(body *ast.BlockStmt) map[string]token.Pos {
	calls := map[string]token.Pos{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			calls[fn.Name] = call.Pos()
		case *ast.SelectorExpr:
			if x, ok := fn.X.(*ast.Ident); ok {
				calls[x.Name+"."+fn.Sel.Name] = call.Pos()
			}
		}
		return true
	})
	return calls
}

// TestAgentRun_ListensThroughValidatedTransport fails if agentRun stops building
// its listening transport through agentListenTransport, or builds one directly.
func TestAgentRun_ListensThroughValidatedTransport(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "agent.go", nil, 0)
	if err != nil {
		t.Fatalf("cannot read agent.go: %v; this test needs the source tree beside it", err)
	}

	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "agentRun" {
			body = fd.Body
			break
		}
	}
	if body == nil {
		t.Fatal("agentRun not found in agent.go; if it was renamed or moved, update this " +
			"test so it keeps guarding the agent's listening transport")
	}

	calls := callsIn(body)

	if _, ok := calls["agentListenTransport"]; !ok {
		t.Error("agentRun does not call agentListenTransport, so the agent's listening " +
			"transport is not the one that validates the source address of new clients")
	}

	// Building a transport directly bypasses the helper, whichever constructor
	// is used: the dial-side one does not validate client source addresses, and
	// the listen-side one belongs inside the helper, not inlined in the run loop.
	var direct []string
	for _, name := range []string{"transport.NewQUICTransport", "transport.NewQUICListenTransport"} {
		if pos, ok := calls[name]; ok {
			direct = append(direct, name+" at "+fset.Position(pos).String())
		}
	}
	sort.Strings(direct)
	if len(direct) > 0 {
		t.Errorf("agentRun builds a transport directly (%s); it must listen through "+
			"agentListenTransport so that new clients' source addresses are validated",
			strings.Join(direct, ", "))
	}
}
