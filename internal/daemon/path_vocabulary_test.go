package daemon

// The words status can use to name a route are a published vocabulary, and four
// of the six name work that does not exist. A document claiming a session was
// relayed when nothing relayed it would be worse than one that said nothing, so
// those four must never be reported until the thing each names is built.
//
// That rule cannot live in a comment. The normative prose is kept elsewhere and
// is not shipped with the source, so it cannot be read by a test; what a test
// can do is refuse to let the unbuilt words appear in this package at all, and
// require every word the classifier can return to come from a named constant.
// This is the same shape as the check that keeps the connection-state vocabulary
// at five words.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

// unbuiltPathWords name routes this program cannot take. Each becomes reportable
// only in the change that makes the route real.
var unbuiltPathWords = []string{
	"router-mapped",
	"punched",
	"bound-proxy",
	"relayed",
}

// builtPathWords are the two routes that exist, and are the only words the
// classifier may return.
var builtPathWords = []string{
	pathIPv4Direct,
	pathIPv6Direct,
}

func parsePackageSource(t *testing.T) (*token.FileSet, map[string]*ast.Package) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("cannot read this package's source: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("no source found beside this test; it needs the source tree to attest anything")
	}
	return fset, pkgs
}

// TestStatusNeverNamesARouteThatDoesNotExist fails if a word for unbuilt work
// appears anywhere in this package's source, whatever it is used for.
func TestStatusNeverNamesARouteThatDoesNotExist(t *testing.T) {
	fset, pkgs := parsePackageSource(t)

	unbuilt := map[string]bool{}
	for _, w := range unbuiltPathWords {
		unbuilt[w] = true
	}

	found := map[string]string{}
	built := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				if unbuilt[v] {
					found[v] = fset.Position(lit.Pos()).String()
				}
				for _, w := range builtPathWords {
					if v == w {
						built[v] = true
					}
				}
				return true
			})
		}
	}

	for word, where := range found {
		t.Errorf("the source can report the route %q (%s), but nothing in this program produces "+
			"that kind of connection. A word is published before it works so the vocabulary is "+
			"fixed, and reported only once it does", word, where)
	}

	// The control: if the two real words have vanished, this test would pass by
	// the feature having been deleted rather than by the rule being kept.
	for _, w := range builtPathWords {
		if !built[w] {
			t.Errorf("the route %q is no longer named anywhere in this package, so this check is "+
				"no longer watching a live vocabulary", w)
		}
	}
}

// TestEveryRouteWordTheClassifierReturnsIsBuilt reads the one function that turns
// an address into a word and requires every word it can return to be a named
// constant for a route that exists. A bare string here would put a word in the
// published vocabulary without it appearing beside the others.
func TestEveryRouteWordTheClassifierReturnsIsBuilt(t *testing.T) {
	_, pkgs := parsePackageSource(t)

	allowed := map[string]bool{}
	for _, w := range builtPathWords {
		allowed[w] = true
	}

	var inspected int
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Name.Name != "pathForAddr" {
					return true
				}
				inspected++
				ast.Inspect(fn, func(inner ast.Node) bool {
					ret, ok := inner.(*ast.ReturnStmt)
					if !ok {
						return true
					}
					for _, res := range ret.Results {
						switch v := res.(type) {
						case *ast.Ident:
							if !allowed[identPathValue(v.Name)] {
								t.Errorf("the classifier can return %s, which does not name a "+
									"route this program can take", v.Name)
							}
						case *ast.BasicLit:
							s, err := strconv.Unquote(v.Value)
							if err == nil && s == "" {
								continue // no route to name is a legitimate answer
							}
							t.Errorf("the classifier returns the bare text %s; every reported word "+
								"must come from a named constant so there is one place to check "+
								"them all", v.Value)
						}
					}
					return true
				})
				return false
			})
		}
	}

	if inspected != 1 {
		t.Fatalf("found %d functions turning an address into a route word, want 1; if it was "+
			"renamed, this check is no longer looking at anything", inspected)
	}
}

// identPathValue maps a constant's name to its value, so the check above can
// compare what a return statement yields against the words that are built.
func identPathValue(name string) string {
	switch name {
	case "pathIPv4Direct":
		return pathIPv4Direct
	case "pathIPv6Direct":
		return pathIPv6Direct
	}
	return name
}
