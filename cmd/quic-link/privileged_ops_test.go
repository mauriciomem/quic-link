package main

// privileged_ops_test.go is a source-level attestation of a product rule:
//
//	quic-link never asks the operating system for elevated privileges, and
//	never runs a tool whose purpose is to grant them. Setup may ask the user
//	for a password once, through their own sudo, to write one configuration
//	file. Nothing this program does at any other time requires it, and nothing
//	this program ships holds a capability, edits a firewall, changes a kernel
//	setting, or reconfigures a network interface.
//
// The rule is deliberately attested from the source rather than from behaviour,
// because the failure it guards against is someone adding a plausible-looking
// escalation years from now to solve a problem that was already decided against.
// A behavioural test would only catch it on the platform where it was added; a
// source test catches it in review, on every platform, forever.
//
// This covers the *escalation* half of the rule. The other half — that no
// listener ever binds a port the operating system reserves — is enforced where
// it belongs, by refusing such a port when configuration is loaded, because a
// port number arrives as data and cannot be attested from source text.
//
// Know what these tests do NOT catch, so nobody trusts them for more than they
// are: a tool name assembled at run time (`"su" + "do"`, a format string, a
// value read from a file) is invisible to a scan of string literals. They catch
// the honest mistake and the casual addition, which is what review needs; they
// are not a defence against someone deliberately hiding an escalation, and
// nothing short of running the binary would be.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// filesAllowedToRunOtherPrograms is the complete set of files that may import
// os/exec. Adding to it is a decision, not a detail: every entry must have a
// reason recorded here.
var filesAllowedToRunOtherPrograms = map[string]string{
	// Launches the user's own ssh client with runtime-only flags, so a name
	// works without editing any file the user owns. It runs ssh as the user,
	// with the user's own credentials, and grants nothing.
	"cmd/quic-link/ssh.go": "runs the user's ssh client, unprivileged",
	// Runs a shell to check how the flags handed to ssh are word-split.
	"cmd/quic-link/ssh_test.go": "runs sh to verify argument quoting",
	// Asks the system resolver to read its configuration again, which is the
	// one thing setup does that is not quic-link. It is why setup exists: the
	// alternative is asking the user to remember the command themselves.
	"cmd/quic-link/initcmd.go": "reloads the system resolver during setup",
	// Asks the system for its own version, to find out whether a resolver here
	// can be pointed at a port at all. Reading only; changes nothing.
	"internal/setup/resolver.go": "asks the system its version before setup decides anything",
}

// privilegeTools are program names whose entire purpose is to grant or use a
// privilege we have decided never to hold. A Go string equal to one of these
// is a command being named. Prose that merely mentions one — a remedy line
// telling the user to run something themselves, for instance — is a longer
// string and is unaffected.
//
// This list is applied to production files only. Tests are excluded on purpose:
// several of them use these very names as the needle in an assertion that a
// message does NOT mention escalating, and forbidding the word there would
// forbid the tests that enforce the rule. Tests are covered instead by the
// import check above, which is what a test would need in order to actually run
// one of these.
var privilegeTools = map[string]string{
	"sudo":      "runs another program as root",
	"doas":      "runs another program as root",
	"pkexec":    "runs another program as root",
	"su":        "runs another program as another user",
	"setcap":    "grants a capability to a binary",
	"ifconfig":  "reconfigures a network interface",
	"ip":        "reconfigures networking on Linux",
	"pfctl":     "loads firewall rules on macOS",
	"nft":       "loads firewall rules on Linux",
	"iptables":  "loads firewall rules on Linux",
	"sysctl":    "changes a kernel setting",
	"launchctl": "loads a system service on macOS",
	"systemctl": "loads a system service on Linux",
}

// moduleRoot walks up from the test's working directory to the directory
// holding go.mod, so the test is independent of where it is invoked from.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod above the working directory")
		}
		dir = parent
	}
}

// eachGoFile visits every .go file under the module root, skipping vendored
// and hidden trees, and reports each file's path relative to the root.
func eachGoFile(t *testing.T, fn func(rel string, file *ast.File, fset *token.FileSet)) {
	t.Helper()
	root := moduleRoot(t)
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		parsed, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			return perr
		}
		fn(filepath.ToSlash(rel), parsed, fset)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// processStarters are the calls that begin another program. os/exec is the
// obvious one; the others are the ways to do it without importing os/exec, and
// leaving them out would mean the allowlist below vouched for nothing.
var processStarters = map[string]bool{
	"os.StartProcess":      true,
	"syscall.Exec":         true,
	"syscall.ForkExec":     true,
	"syscall.StartProcess": true,
	"unix.Exec":            true,
}

// TestOnlyAllowlistedFilesRunOtherPrograms asserts that the set of files able
// to start another process is exactly the recorded set. A new importer of
// os/exec — or a caller of one of the lower-level ways to spawn a program —
// fails here, which is the point: starting a program is how every escalation
// would have to begin.
func TestOnlyAllowlistedFilesRunOtherPrograms(t *testing.T) {
	found := map[string]bool{}

	eachGoFile(t, func(rel string, file *ast.File, fset *token.FileSet) {
		if rel == "cmd/quic-link/privileged_ops_test.go" {
			return // names the calls as data
		}
		for _, imp := range file.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if p == "os/exec" {
				found[rel] = true
			}
		}
		// syscall and x/sys/unix are imported all over for errno constants, so
		// the import alone means nothing; it is the call that matters.
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if processStarters[pkg.Name+"."+sel.Sel.Name] {
				found[rel] = true
			}
			return true
		})
	})

	for rel := range found {
		if _, ok := filesAllowedToRunOtherPrograms[rel]; !ok {
			t.Errorf("%s starts other programs but is not on the allowlist.\n"+
				"If this is deliberate, add it with the reason it is safe; if it is an\n"+
				"escalation, it is not something this program does.", rel)
		}
	}
	for rel, why := range filesAllowedToRunOtherPrograms {
		if !found[rel] {
			t.Errorf("%s is allowlisted (%q) but no longer starts other programs; "+
				"remove the entry so the list stays a true statement", rel, why)
		}
	}
}

// TestNoSourceNamesAPrivilegeTool asserts that no Go string in production code
// is exactly the name of a program that grants or uses privilege.
func TestNoSourceNamesAPrivilegeTool(t *testing.T) {
	eachGoFile(t, func(rel string, file *ast.File, fset *token.FileSet) {
		if strings.HasSuffix(rel, "_test.go") {
			return
		}
		// A file that is allowed to start programs may name the programs it
		// starts; that is what the review of its allowlist entry was for.
		if _, allowed := filesAllowedToRunOtherPrograms[rel]; allowed {
			return
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if why, bad := privilegeTools[val]; bad {
				t.Errorf("%s:%d names %q, which %s.\n"+
					"Naming it as a bare string is how it would be run. Prose that tells\n"+
					"the user to run something themselves is a longer string and is fine.",
					rel, fset.Position(lit.Pos()).Line, val, why)
			}
			return true
		})
	})
}
