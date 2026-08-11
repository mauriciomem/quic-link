package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoTestClosesTheProcessStdout guards a defect that made this package's
// test results untrustworthy: a test called a method that closes os.Stdout,
// and for a test binary that is the descriptor the testing framework writes
// its results to. Every result line after it vanished, so a failing test could
// be reported as nothing but a bare package-level failure naming no test at
// all. Twenty results were lost, and the run still looked like an ordinary
// failure.
//
// Closing this process's stdout is therefore banned in this package's tests.
// The methods that do it are proven to exist by the compiler, which is all the
// coverage they need here; behaviour that requires a real stream belongs in
// the package that owns the splice, where the streams are pipes nobody needs
// for reporting.
//
// The scan is textual on purpose. The alternative is to observe the damage,
// and the damage is precisely that observations stop being reported.
func TestNoTestClosesTheProcessStdout(t *testing.T) {
	banned := []string{
		"os.Stdout.Close()",
		"os.Stdin.Close()",
		".CloseWrite()",
		".Close()",
	}
	// Close() and CloseWrite() are only dangerous on the stdio streams
	// wrapper, so the scan looks for them on a receiver of that type.
	riskyReceivers := []string{"stdioRW", "rw."}

	entries, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("glob test files: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no test files found; this guard would pass vacuously")
	}

	for _, name := range entries {
		if name == "stdout_discipline_test.go" {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx]
			}
			if strings.TrimSpace(code) == "" {
				continue
			}
			for _, bad := range banned {
				if !strings.Contains(code, bad) {
					continue
				}
				if bad == "os.Stdout.Close()" || bad == "os.Stdin.Close()" {
					t.Errorf("%s:%d closes this process's standard stream, which hides every test result after it: %s",
						name, i+1, strings.TrimSpace(line))
					continue
				}
				for _, recv := range riskyReceivers {
					if strings.Contains(code, recv) {
						t.Errorf("%s:%d calls %s on the stdio streams wrapper, which closes this process's stdout and hides every test result after it: %s",
							name, i+1, bad, strings.TrimSpace(line))
					}
				}
			}
		}
	}
}
