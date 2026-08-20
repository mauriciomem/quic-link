package ipc

// A guard for the way this package is split across platforms.
//
// peerUID has one implementation per credential mechanism and one fallback that
// refuses. Exactly one of them must apply to any given operating system: if two
// applied the package would not compile, and if none applied it would not
// compile either — which is what happened when the shared BSD implementation
// carried a filename ending in _darwin. Go reads that suffix as a build
// constraint and combines it with the //go:build line using AND, so FreeBSD
// silently matched nothing and the package lost peerUID entirely on that
// platform.
//
// That failure was loud, but only for someone who happened to build for
// FreeBSD. This test makes the intent checkable on any machine, by reading the
// build constraints the way the toolchain does rather than by compiling for
// every target.

import (
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// platformsServingPeerUID lists every operating system this package intends to
// serve with a real credential check, and the file expected to provide it. A
// platform absent from this map is expected to fall through to the refusing
// fallback — which is a deliberate choice, not an oversight: OpenBSD and NetBSD
// offer none of LOCAL_PEERCRED, SOL_LOCAL or Xucred, so there is nothing to
// call there.
var platformsServingPeerUID = map[string]string{
	"linux":   "peercred_linux.go",
	"darwin":  "peercred_bsd.go",
	"freebsd": "peercred_bsd.go",
}

// platformsRefusing lists operating systems expected to get the fallback, whose
// peerUID always fails so the accept loop refuses the connection rather than
// trusting an unchecked peer.
var platformsRefusing = []string{"openbsd", "netbsd", "windows"}

// peerCredFileFor reports which peercred file the toolchain selects for goos,
// honouring both the //go:build lines and the implicit constraint carried by a
// filename suffix.
func peerCredFileFor(t *testing.T, goos string) []string {
	t.Helper()
	ctx := build.Default
	ctx.GOOS = goos
	// The architecture is irrelevant to these constraints, but it must be one
	// the target actually has, or the toolchain rejects the combination.
	ctx.GOARCH = "amd64"
	ctx.CgoEnabled = false

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	pkg, err := ctx.ImportDir(dir, 0)
	if err != nil {
		t.Fatalf("importing this directory for %s: %v", goos, err)
	}
	var selected []string
	for _, f := range pkg.GoFiles {
		if strings.HasPrefix(f, "peercred_") {
			selected = append(selected, f)
		}
	}
	return selected
}

// TestEveryPlatformGetsExactlyOnePeerUID pins that the split is total and
// non-overlapping. A platform with two implementations does not compile; a
// platform with none does not compile either, and that is the shape that
// survived unnoticed.
func TestEveryPlatformGetsExactlyOnePeerUID(t *testing.T) {
	all := append([]string{}, platformsRefusing...)
	for goos := range platformsServingPeerUID {
		all = append(all, goos)
	}
	for _, goos := range all {
		got := peerCredFileFor(t, goos)
		if len(got) != 1 {
			t.Errorf("%s selects %d peercred files (%v); exactly one must apply, "+
				"or the package either fails to compile or has no peer-credential check",
				goos, len(got), got)
		}
	}
}

// TestPlatformsWithACredentialMechanismGetTheRealCheck pins which file serves
// each platform that has a mechanism. Renaming a file so that its name narrows
// its own build constraint fails here, naming the platform that lost its
// implementation.
func TestPlatformsWithACredentialMechanismGetTheRealCheck(t *testing.T) {
	for goos, want := range platformsServingPeerUID {
		got := peerCredFileFor(t, goos)
		if len(got) == 1 && got[0] == want {
			continue
		}
		t.Errorf("%s selects %v, want exactly [%s] — a filename ending in an "+
			"operating-system name constrains the file to that system on top of "+
			"its //go:build line, which is how a shared implementation stops "+
			"applying to the platforms it names",
			goos, got, want)
	}
}

// TestPlatformsWithoutAMechanismRefuseRatherThanAllow pins that an unsupported
// platform gets the fallback. The fallback's peerUID always returns an error and
// the accept loop treats that as fatal, so such a build starts and then refuses
// every connection. That is the safe direction, and it is worth knowing it is
// the direction chosen: the alternative would be a daemon that accepts a peer it
// cannot identify.
func TestPlatformsWithoutAMechanismRefuseRatherThanAllow(t *testing.T) {
	for _, goos := range platformsRefusing {
		got := peerCredFileFor(t, goos)
		if len(got) == 1 && got[0] == "peercred_other.go" {
			continue
		}
		t.Errorf("%s selects %v, want exactly [peercred_other.go] — a platform with "+
			"no credential mechanism must reach the refusing fallback", goos, got)
	}
}

// TestNoPeerCredFileCarriesAnOSSuffixItDoesNotMean is the direct guard against
// the original mistake. A file whose //go:build line names several operating
// systems must not carry a filename suffix naming one of them, because the
// suffix silently wins for all the others.
func TestNoPeerCredFileCarriesAnOSSuffixItDoesNotMean(t *testing.T) {
	entries, err := filepath.Glob("peercred_*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no peercred files found; this test is looking in the wrong place")
	}
	// Every GOOS Go recognises as a filename constraint that this package cares
	// about. A file named for one of these is constrained to it.
	known := []string{"linux", "darwin", "freebsd", "openbsd", "netbsd", "windows"}
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		constraint := ""
		for _, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(line, "//go:build ") {
				constraint = line
				break
			}
		}
		if constraint == "" {
			t.Errorf("%s has no //go:build line, so which platforms it serves is implicit", path)
			continue
		}
		named := 0
		for _, goos := range known {
			if strings.Contains(constraint, goos) && !strings.Contains(constraint, "!"+goos) {
				named++
			}
		}
		base := strings.TrimSuffix(path, ".go")
		for _, goos := range known {
			if !strings.HasSuffix(base, "_"+goos) {
				continue
			}
			if named > 1 {
				t.Errorf("%s names %d operating systems in %q but its filename ends in _%s, "+
					"which constrains it to %s alone and silently drops the others",
					path, named, strings.TrimPrefix(constraint, "//go:build "), goos, goos)
			}
		}
	}
}
