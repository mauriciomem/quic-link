/**
 * @spec-handoff
 * @interface guard only - no production interface. Scans the module's non-test Go files with go/ast.
 * @behavior
 *   - no non-test .go file outside internal/identity references PairingTLS, ListenTLSWithPairing,
 *     AgentListenTLSFrom or AgentDialTLSFrom (any identifier with that exact name)
 *   - no non-test .go file outside internal/pairstate imports internal/pairstate (or a package below it)
 *   - the scan is not vacuous: it must see each of the four names declared as a function in internal/identity
 *     and at least one production import of internal/identity, or the test fails
 * @edge-cases
 *   - skipped: _test.go files, testdata, vendor, dot- and underscore-prefixed dirs, nested modules
 *   - the detector itself is checked on a synthetic file (flags all five, and honors the two exemptions)
 * @see ../../internal/identity/tls.go
 */
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// pairingSurface is the unwired pairing API that only internal/identity may
// reference until a listener is deliberately wired to it.
var pairingSurface = []string{"PairingTLS", "ListenTLSWithPairing", "AgentListenTLSFrom", "AgentDialTLSFrom"}

// pairingSurfaceViolations lists the pairing-surface references in one parsed
// production file. inIdentity exempts the surface names, inPairstate the
// pairstate import.
func pairingSurfaceViolations(fset *token.FileSet, f *ast.File, modPath string, inIdentity, inPairstate bool) []string {
	var out []string
	pairstate := modPath + "/internal/pairstate"
	if !inPairstate {
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == pairstate || strings.HasPrefix(p, pairstate+"/") {
				out = append(out, fset.Position(imp.Pos()).String()+": imports "+p)
			}
		}
	}
	if !inIdentity {
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && slices.Contains(pairingSurface, id.Name) {
				out = append(out, fset.Position(id.Pos()).String()+": references "+id.Name)
			}
			return true
		})
	}
	return out
}

func TestPairingSurface_NotWired(t *testing.T) {
	root := seamModuleRoot(t)
	modPath := seamModulePath(t, root)
	identityDir := filepath.Join(root, "internal", "identity")
	pairstateDir := filepath.Join(root, "internal", "pairstate")
	identityImport := modPath + "/internal/identity"

	declared := map[string]bool{}
	sawIdentityImport := false
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir // a nested module is not part of this build
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
		dir := filepath.Dir(path)
		inIdentity := dir == identityDir
		inPairstate := dir == pairstateDir || strings.HasPrefix(dir, pairstateDir+string(filepath.Separator))
		for _, v := range pairingSurfaceViolations(fset, f, modPath, inIdentity, inPairstate) {
			t.Errorf("pairing surface wired into production code: %s", v)
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == identityImport {
				sawIdentityImport = true
			}
		}
		if inIdentity {
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && slices.Contains(pairingSurface, fn.Name.Name) {
					declared[fn.Name.Name] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}
	for _, name := range pairingSurface {
		if !declared[name] {
			t.Errorf("scan never saw %s declared in internal/identity: the guard is blind to it", name)
		}
	}
	if !sawIdentityImport {
		t.Error("scan never saw a production import of internal/identity: the import check is blind")
	}

	t.Run("detector flags a synthetic wiring", func(t *testing.T) {
		const mod = "example.test/m"
		src := `package x

import (
	"example.test/m/internal/identity"
	"example.test/m/internal/pairstate"
	_ "example.test/m/internal/pairstate/sub"
	_ "example.test/m/internal/pairstatex"
)

var _ = pairstate.X
var _ = identity.PairingTLS

func f() {
	identity.ListenTLSWithPairing(nil, nil, nil)
	identity.AgentListenTLSFrom(nil, nil)
	identity.AgentDialTLSFrom(nil, nil)
}
`
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Join(pairingSurfaceViolations(fset, f, mod, false, false), "\n")
		for _, want := range []string{
			"imports " + mod + "/internal/pairstate\n",
			"imports " + mod + "/internal/pairstate/sub",
			"references PairingTLS", "references ListenTLSWithPairing",
			"references AgentListenTLSFrom", "references AgentDialTLSFrom",
		} {
			if !strings.Contains(got+"\n", want) {
				t.Errorf("detector missed %q; got:\n%s", strings.TrimSpace(want), got)
			}
		}
		if strings.Contains(got, "pairstatex") {
			t.Errorf("detector flagged a lookalike import path: %s", got)
		}
		if v := pairingSurfaceViolations(fset, f, mod, true, true); len(v) != 0 {
			t.Errorf("exemptions ignored: %v", v)
		}
	})
}
