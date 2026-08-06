package setup

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Scope says who owns a file, which decides who may write it.
type Scope int

const (
	// User files live in the invoking user's home and are written by an
	// ordinary run.
	User Scope = iota
	// Root files live under /etc and are written by a run under sudo.
	Root
)

func (s Scope) String() string {
	if s == Root {
		return "root"
	}
	return "user"
}

// Artifact is one file quic-link puts on the machine. The list of these is the
// complete answer to "what did this do to my system", which is why it is built
// in one place and both the setup verb and the diagnosis verb read it.
type Artifact struct {
	Path  string
	Scope Scope
	// Content is what quic-link writes. When it is empty the file is one we
	// only look for — your settings and your identity are yours to write, and
	// asking whether they carry our marker would be answering the wrong
	// question about them.
	Content []byte
	// What this file achieves, in a few words, for the plan and the report.
	Purpose string

	// Filled in by Survey.
	Present bool
	Ours    bool
	Current bool
	Err     error
}

// Inventory is every file quic-link would install for a given configuration.
//
// dnsPort and suffix come from validated configuration; nothing here re-checks
// them, because a value that reached this point has already been refused if it
// was dangerous.
func Inventory(suffix string, dnsPort int, home string) []Artifact {
	var out []Artifact

	if runtime.GOOS == "darwin" {
		out = append(out, Artifact{
			Path:    filepath.Join("/etc/resolver", suffix),
			Scope:   Root,
			Purpose: fmt.Sprintf("send lookups ending in %s to this machine's responder", suffix),
			Content: Body(
				"nameserver 127.0.0.1",
				fmt.Sprintf("port %d", dnsPort),
			),
		})
	} else {
		out = append(out, Artifact{
			Path:    "/etc/systemd/resolved.conf.d/quic-link.conf",
			Scope:   Root,
			Purpose: fmt.Sprintf("send lookups ending in %s to this machine's responder", suffix),
			Content: Body(
				"[Resolve]",
				fmt.Sprintf("DNS=127.0.0.1:%d", dnsPort),
				fmt.Sprintf("Domains=~%s", suffix),
			),
		})
	}

	return out
}

// Survey fills in what is currently on disk for each artifact.
func Survey(arts []Artifact) []Artifact {
	out := make([]Artifact, len(arts))
	copy(out, arts)
	for i := range out {
		present, ours, err := Inspect(out[i].Path)
		out[i].Present, out[i].Err = present, err
		if len(out[i].Content) == 0 {
			// Not a file we write: present or absent is the whole story.
			out[i].Ours, out[i].Current = present, present
			continue
		}
		out[i].Ours = ours
		if present && ours {
			if b, rerr := os.ReadFile(out[i].Path); rerr == nil {
				out[i].Current = string(b) == string(out[i].Content)
			}
		}
	}
	return out
}

// Missing reports the artifacts that still need writing.
func Missing(arts []Artifact) []Artifact {
	var out []Artifact
	for _, a := range arts {
		if !a.Present || !a.Current {
			out = append(out, a)
		}
	}
	return out
}

// UserPaths are the files an ordinary run looks after. They are listed
// separately from Inventory because they are found relative to a home
// directory, and a privileged run must not go looking for one.
func UserPaths(home, keyFile, configFile string) []Artifact {
	arts := []Artifact{
		{Path: configFile, Scope: User, Purpose: "your settings"},
		{Path: keyFile, Scope: User, Purpose: "this machine's identity"},
	}
	if runtime.GOOS == "darwin" {
		arts = append(arts, Artifact{
			Path:    filepath.Join(home, "Library/LaunchAgents/io.quic-link.daemon.plist"),
			Scope:   User,
			Purpose: "start the daemon when you log in",
		})
	} else {
		arts = append(arts, Artifact{
			Path:    filepath.Join(home, ".config/systemd/user/quic-link.service"),
			Scope:   User,
			Purpose: "start the daemon when you log in",
		})
	}
	return arts
}

// RealUser reports the account that invoked a privileged run, and whether the
// process is privileged at all.
//
// This exists because a privileged run must never write into a home directory.
// Under sudo the home directory reported by the operating system belongs to
// root, so a setup step that created an identity key there would put it
// somewhere the daemon — which runs as the ordinary user — would never look.
// The daemon would then make a different key, and every connection would fail
// to authenticate for reasons that point nowhere near setup.
func RealUser() (name string, privileged bool) {
	if os.Geteuid() != 0 {
		return "", false
	}
	return os.Getenv("SUDO_USER"), true
}

// DescribeInventory renders the artifact list for a person to read.
func DescribeInventory(arts []Artifact) string {
	var b strings.Builder
	for _, a := range arts {
		mark := "absent"
		switch {
		case a.Err != nil:
			mark = "PROBLEM"
		case a.Present && a.Ours && a.Current:
			mark = "present"
		case a.Present && a.Ours:
			mark = "out of date"
		case a.Present:
			mark = "not ours"
		}
		fmt.Fprintf(&b, "  %-8s %-6s %s\n", mark, a.Scope, a.Path)
		if a.Err != nil {
			fmt.Fprintf(&b, "           %v\n", a.Err)
		}
	}
	return b.String()
}
