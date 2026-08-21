package main

// A guard for the length of the unix-socket paths tests create.
//
// A unix socket address is limited to 104 bytes on macOS and 108 on Linux, and
// this project enforces the smaller of the two everywhere. Tests that need a
// socket point XDG_RUNTIME_DIR at a private directory, and the obvious way to
// make one — t.TempDir — builds its path from TMPDIR and the test's own name.
// That is fine on Linux, where TMPDIR is normally /tmp and the longest name here
// leaves three bytes of headroom. It is not fine on macOS, where TMPDIR is a
// per-user directory under /var/folders of about fifty characters, and the
// socket cannot be bound at all.
//
// The failure gives no hint of its cause: "bind: invalid argument", or, on the
// dial side, an error about a socket "occupied by an unrecognized process". Both
// read as something other than a path being too long, which is why this test
// exists rather than a comment.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allTestFiles returns every _test.go file in the module, so this guard covers
// the packages the mistake actually spread to rather than only its own.
func allTestFiles(t *testing.T) ([]string, error) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		return nil, err
	}
	var out []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
		if strings.HasSuffix(path, "_test.go") {
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return rerr
			}
			out = append(out, rel)
		}
		return nil
	})
	return out, err
}

// sunPathBudget is the limit this project enforces for a socket address, matching
// the constant in the production path resolver. Kept as a literal rather than
// imported so that a change to one has to be made deliberately in both.
const sunPathBudget = 104

// TestShortTempDirLeavesRoomForASocket pins that the helper tests use for socket
// directories produces a path a socket actually fits in, whatever TMPDIR says.
//
// The subtests set TMPDIR to the two shapes that matter: the short one Linux
// gives, and the long one macOS gives.
func TestShortTempDirLeavesRoomForASocket(t *testing.T) {
	// The longest test name in this package that also creates a socket. Go's
	// TempDir appends the test name plus a random number, so this is the worst
	// case a socket-creating test can present.
	longestName := "TestStatusPlain_OutputByteIdentical_WithAndWithoutRoutesWired"

	// What the daemon appends to XDG_RUNTIME_DIR to reach its socket.
	suffix := filepath.Join("quic-link", "daemon.sock")

	for _, tmpdir := range []string{
		"/tmp",
		// A realistic macOS per-user temp directory.
		"/var/folders/q1/8k2p3n5d7x9v0m4l6j8h2g4f0000gn/T",
	} {
		t.Run(strings.ReplaceAll(tmpdir, "/", "_"), func(t *testing.T) {
			t.Setenv("TMPDIR", tmpdir)

			dir := shortTempDir(t)
			full := filepath.Join(dir, suffix)
			if len(full) > sunPathBudget {
				t.Errorf("with TMPDIR=%s the helper produced %s, which is %d bytes and "+
					"exceeds the %d-byte socket limit; a test using it could not bind",
					tmpdir, full, len(full), sunPathBudget)
			}

			// And show what the discouraged approach would have produced, so the
			// margin is visible rather than asserted. This is the comparison that
			// explains why the helper exists.
			viaTempDir := filepath.Join(tmpdir, longestName+"1234567890", "001", suffix)
			if len(viaTempDir) <= sunPathBudget {
				t.Logf("note: with TMPDIR=%s even t.TempDir would have fit (%d bytes); "+
					"the helper is what makes that true on the other platform too",
					tmpdir, len(viaTempDir))
			} else {
				t.Logf("t.TempDir would have produced %d bytes here, over the %d-byte limit; "+
					"the helper produced %d", len(viaTempDir), sunPathBudget, len(full))
			}
		})
	}
}

// TestNoTestPointsTheSocketDirAtTempDir is the direct guard against the mistake
// returning. A test that sets XDG_RUNTIME_DIR to t.TempDir() works on Linux and
// fails on macOS, so it would pass review and pass locally and then fail in CI
// on one platform only — which is exactly how the four cases this guard was
// written for were found.
//
// It scans the whole module rather than this package, because the same mistake
// occurred independently in internal/ipc, internal/router and internal/tunnel,
// each with its own local workaround or none. A guard that watched one package
// would have reported success while three others were broken.
func TestNoTestPointsTheSocketDirAtTempDir(t *testing.T) {
	entries, err := allTestFiles(t)
	if err != nil {
		t.Fatalf("finding test files: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no test files found; this test is looking in the wrong place")
	}
	for _, path := range entries {
		// This file has to name the pattern it forbids in order to describe it,
		// so it is not a candidate for its own check.
		if strings.HasSuffix(path, "socket_path_length_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, `"XDG_RUNTIME_DIR"`) && strings.Contains(line, "t.TempDir()") {
				t.Errorf(`%s:%d points XDG_RUNTIME_DIR at t.TempDir(), whose path includes `+
					`TMPDIR and the test name. That fits on Linux and does not on macOS, `+
					`where the socket cannot be bound. Use a directory taken from /tmp instead.`,
					path, i+1)
			}
			// A socket path built directly out of t.TempDir has the same problem,
			// and is how it reached three other packages.
			if strings.Contains(line, "t.TempDir()") &&
				(strings.Contains(line, ".sock") || strings.Contains(line, "unix://")) {
				t.Errorf(`%s:%d builds a unix socket path from t.TempDir(), whose path `+
					`includes TMPDIR and the test name. On macOS that exceeds the `+
					`104-byte socket limit and fails with "bind: invalid argument", which `+
					`names no length. Take the directory from /tmp instead.`,
					path, i+1)
			}
		}
	}
}
