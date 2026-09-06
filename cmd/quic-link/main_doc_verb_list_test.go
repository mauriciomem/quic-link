package main

// main_doc_verb_list_test.go couples the verb list in main.go's package doc
// comment to the commands root.go actually registers, in one direction only:
// every verb the doc comment names must be a command newRootCmd() registers.
// The reverse is not checked, and it must not be added.
//
// The doc comment's list is a curated shortlist, not the full command set --
// main.go's own prose says so, and six registered commands are left off on
// purpose (connect, vhosts, fwd, expose, init, doctor). Enforcing the reverse
// direction would turn that editorial choice into a build failure and force
// every future verb onto the shortlist, which is exactly what
// docs/contributing/add-a-verb.md tells a contributor not to do. This test
// only catches the one thing that is unambiguously a bug: a verb named in the
// list that no longer exists, because it was renamed or removed in root.go
// without the doc comment being updated to match.

import (
	"go/doc"
	"go/doc/comment"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// mainDocText reads this package's own source and returns main.go's raw
// package doc comment text, before go/doc/comment classifies any of it as a
// *comment.Code block. mainDocListedVerbs and mainDocRawVerbLineCount both
// parse this same string -- from two independent angles -- so this is the
// one place that reads the source.
func mainDocText(t *testing.T) string {
	t.Helper()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("cannot read this package's source: %v", err)
	}
	pkg, ok := pkgs["main"]
	if !ok {
		t.Fatal("no \"main\" package found beside this test; it needs main.go's own doc " +
			"comment to attest anything")
	}

	return doc.New(pkg, ".", doc.AllDecls).Doc
}

// mainDocListedVerbs parses docText with go/doc/comment and returns every
// verb named on a "quic-link <verb>" line inside a *comment.Code block, in
// source order. It returns nil if the block is missing or contains no such
// line -- the caller enforces the vacuity guard on that.
func mainDocListedVerbs(docText string) []string {
	var cp comment.Parser
	parsed := cp.Parse(docText)

	var verbs []string
	for _, block := range parsed.Content {
		code, ok := block.(*comment.Code)
		if !ok {
			continue
		}
		for _, line := range strings.Split(code.Text, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "quic-link" {
				verbs = append(verbs, fields[1])
			}
		}
	}
	return verbs
}

// mainDocRawVerbLineCount independently counts "quic-link <verb>  -- ..."
// lines in docText by scanning its raw text directly, without going through
// go/doc/comment's *comment.Code classification at all. A line counts only
// if it starts with "quic-link" *and* separately carries a bare "--" field
// further along, matching the actual shape of a verb-table row; fields[0]
// alone is not enough; the doc comment's wrapped prose happens to contain a
// line starting with the literal word "quic-link" too ("quic-link
// registers. See docs/cli.md's ..."), and that line must not count.
//
// It exists purely as a cross-check against mainDocListedVerbs: the two
// functions must agree, because every real verb-table row is supposed to
// live inside the recognized code block. If they disagree, some verb line
// failed *comment.Code classification -- e.g. because it was de-indented --
// even though enough other lines still passed to keep the plain zero-verbs
// vacuity check below from firing. A bare minimum-count constant would catch
// that too, but it would need updating by hand every time a verb is added to
// or removed from main.go's list, which is exactly the kind of unenforced,
// drift-prone number this test exists to avoid introducing elsewhere.
// Comparing two independent counts of the same source catches an undercount
// without needing to know what the "right" count is.
func mainDocRawVerbLineCount(docText string) int {
	n := 0
	for _, line := range strings.Split(docText, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "quic-link" {
			continue
		}
		for _, f := range fields[2:] {
			if f == "--" {
				n++
				break
			}
		}
	}
	return n
}

// TestMainDocVerbListMatchesRegistrations fails if a verb named in main.go's
// doc-comment code block is not a command newRootCmd() actually registers.
func TestMainDocVerbListMatchesRegistrations(t *testing.T) {
	docText := mainDocText(t)
	verbs := mainDocListedVerbs(docText)
	if len(verbs) == 0 {
		t.Fatal("main.go's package doc comment has no recognizable verb list: either the " +
			"*comment.Code block is missing, or it contains no \"quic-link <verb>\" line. " +
			"go/doc/comment classifies the bulleted list as code only because each line is " +
			"indented; de-indenting it into a plain paragraph, or restyling it with \"- \" " +
			"bullets, makes it invisible to this test (and to `go doc`) without producing any " +
			"other error. Restore the indented \"quic-link <verb>  -- ...\" lines under the " +
			"package comment.")
	}
	if raw := mainDocRawVerbLineCount(docText); len(verbs) != raw {
		t.Fatalf("go/doc/comment's *comment.Code block recognized %d \"quic-link <verb>\" "+
			"line(s), but a raw scan of the same doc comment text finds %d such line(s). A "+
			"*partial* de-indent (or a switch to \"- \" bullets on only some lines) can drop "+
			"individual verb lines out of the code block without dropping them all, which "+
			"would otherwise leave this test silently checking fewer verbs than main.go "+
			"actually documents while still reporting green. Restore consistent tab "+
			"indentation on every \"quic-link <verb>  -- ...\" line.", len(verbs), raw)
	}

	root := newRootCmd()
	registered := map[string]bool{}
	var names []string
	for _, cmd := range root.Commands() {
		registered[cmd.Name()] = true
		names = append(names, cmd.Name())
	}
	if len(registered) == 0 {
		t.Fatal("newRootCmd().Commands() registered nothing, so there is no registered " +
			"command set to compare main.go's doc comment against. Check root.go's " +
			"root.AddCommand call.")
	}
	sort.Strings(names)

	for _, verb := range verbs {
		if !registered[verb] {
			t.Errorf("main.go's doc comment names %q as a subcommand, but newRootCmd() does "+
				"not register any command by that name. The list is a curated shortlist and "+
				"may omit real verbs, but every verb it does name must exist: if %q was "+
				"renamed or removed in root.go, update or delete its line in main.go's doc "+
				"comment (see docs/contributing/add-a-verb.md). Commands newRootCmd() "+
				"actually registers: %v", verb, verb, names)
		}
	}

	t.Run("serve alias", func(t *testing.T) {
		for _, cmd := range root.Commands() {
			for _, alias := range cmd.Aliases {
				if alias != "serve" {
					continue
				}
				if cmd.Name() != "agent" {
					t.Errorf("\"serve\" is registered as an alias of %q, not \"agent\"; "+
						"main.go's doc comment says \"serve\" aliases \"agent\" -- update "+
						"whichever one is now wrong", cmd.Name())
				}
				return
			}
		}
		t.Error("no registered command lists \"serve\" as an alias; main.go's doc comment " +
			"says \"serve\" is a deprecated alias for \"agent\", but nothing in root.go's " +
			"registrations backs that claim any longer")
	})

	t.Run("connect alias", func(t *testing.T) {
		if !registered["connect"] {
			t.Error("no registered command named \"connect\"; main.go's doc comment says " +
				"\"connect\" is a deprecated alias for \"daemon --server NAME\", but root.go " +
				"no longer registers a command with that name")
		}
	})
}
