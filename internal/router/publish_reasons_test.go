package router

// Two rules here were once justified by there being no way to take a published
// name back. There is now, so those justifications are gone while both rules
// stand — each on a reason that never depended on withdrawal. An idempotent
// repeat is kept because it makes publishing safe to retry when a reply may have
// been lost, and a runtime wildcard is refused because it would claim every name
// nobody has claimed yet, including ones the operator has not chosen.
//
// The old wording is the kind of thing that comes back: somebody reads a rule,
// looks for why, finds nothing, and writes the reason that first occurs to them.
// This fails if it does, and says which sentence to replace.

import (
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

func TestNoPublishRuleIsJustifiedByAnAbsentWithdrawal(t *testing.T) {
	stale := []string{
		"no way to withdraw",
		"no way to unpublish",
		"agent restart as the only way",
		"could not be taken back",
		"cannot be taken back",
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("cannot read this package's source: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("no source found beside this test; it needs the source tree to check anything")
	}

	var files int
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			files++
			for _, group := range file.Comments {
				text := group.Text()
				for _, phrase := range stale {
					if strings.Contains(text, phrase) {
						t.Errorf("%s: a comment still explains a rule by saying a published name "+
							"cannot be taken back (%q). It can now. The rule itself is right; give "+
							"it the reason that does not depend on withdrawal.",
							name, phrase)
					}
				}
			}
		}
	}
	if files == 0 {
		t.Fatal("no files were examined, so this check proved nothing")
	}
}
