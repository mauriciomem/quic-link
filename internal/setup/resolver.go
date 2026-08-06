package setup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Support says whether registering names with this machine's resolver will
// work, and if not, why not.
type Support int

const (
	// Unsupported means there is no way to point this machine's resolver at a
	// port without asking for privileges at runtime, which is never done.
	Unsupported Support = iota
	// SystemdStub means systemd-resolved is the system resolver and every
	// lookup passes through it, so a drop-in takes effect.
	SystemdStub
	// MacResolver means the per-domain resolver directory macOS reads.
	MacResolver
)

func (s Support) String() string {
	switch s {
	case SystemdStub:
		return "systemd-resolved"
	case MacResolver:
		return "macOS resolver directory"
	default:
		return "unsupported"
	}
}

// minSystemdVersion is the first release that lets a resolver be named with a
// port. Without that, pointing the system at an unprivileged responder is not
// expressible, and the only alternative would be to take a privileged port.
const minSystemdVersion = 247

// Resolver describes what this machine can do, and what to tell the user when
// it cannot do it.
type Resolver struct {
	Support Support
	// Reason explains an Unsupported result in a sentence a user can act on.
	Reason string
	// Manual is the recipe to print when we will not do it ourselves.
	Manual string
	// SystemdVersion is 0 when it could not be determined.
	SystemdVersion int
}

// runner runs a program and returns its output. It exists so the branching
// below can be tested against the output real systems produce, without needing
// those systems. It wraps the exact call the program makes.
type runner interface {
	run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, path, args...).Output()
}

// DetectResolver works out whether names can be registered here.
func DetectResolver(ctx context.Context) Resolver {
	return detectResolver(ctx, execRunner{}, "/")
}

func detectResolver(ctx context.Context, r runner, root string) Resolver {
	if runtime.GOOS == "darwin" {
		return Resolver{
			Support: MacResolver,
			Manual:  macManual(),
		}
	}
	return detectSystemd(ctx, r, root)
}

// detectSystemd decides whether a drop-in will actually be honoured.
//
// Whether systemd-resolved is running is the wrong question. It has two modes,
// and only one of them reads what we would write. When every lookup goes
// through its local listener, a drop-in takes effect; when programs are handed
// the upstream servers directly instead, the drop-in is accepted and quietly
// does nothing. Checking that the service is active cannot tell those apart,
// so what is checked is where the system's resolver configuration points.
func detectSystemd(ctx context.Context, r runner, root string) Resolver {
	res := Resolver{Manual: systemdManual()}

	link, err := os.Readlink(filepath.Join(root, "etc/resolv.conf"))
	if err != nil {
		res.Reason = "this machine's resolver configuration is a plain file, not managed by " +
			"systemd-resolved, and a plain resolver configuration cannot name a port"
		return res
	}
	if !strings.Contains(link, "stub-resolv.conf") {
		res.Reason = "systemd-resolved is present but is not handling lookups for this machine " +
			"(its resolver configuration points at " + filepath.Base(link) + " rather than the " +
			"local listener), so anything registered with it would be ignored"
		return res
	}

	out, err := r.run(ctx, "systemctl", "--version")
	if err != nil {
		res.Reason = "systemd-resolved appears to be handling lookups, but its version could " +
			"not be determined, and naming a resolver with a port needs a recent enough release"
		return res
	}
	v := parseSystemdVersion(string(out))
	res.SystemdVersion = v
	if v == 0 {
		res.Reason = "the systemd version could not be read from its own output"
		return res
	}
	if v < minSystemdVersion {
		res.Reason = fmt.Sprintf(
			"this machine runs systemd %d, and naming a resolver together with a port needs %d "+
				"or later; on older releases there is no way to point the system at an "+
				"unprivileged responder", v, minSystemdVersion)
		return res
	}

	res.Support = SystemdStub
	return res
}

// parseSystemdVersion pulls the release number out of the version banner.
// The text in parentheses differs between distributions; the bare number after
// the name does not.
func parseSystemdVersion(out string) int {
	fields := strings.Fields(out)
	for i, f := range fields {
		if !strings.EqualFold(f, "systemd") || i+1 >= len(fields) {
			continue
		}
		tok := strings.TrimPrefix(fields[i+1], "v")
		end := 0
		for end < len(tok) && tok[end] >= '0' && tok[end] <= '9' {
			end++
		}
		if end == 0 {
			continue
		}
		if n, err := strconv.Atoi(tok[:end]); err == nil {
			return n
		}
	}
	return 0
}

func systemdManual() string {
	return strings.Join([]string{
		"To do this by hand, point your resolver at the responder for your suffix.",
		"With systemd-resolved that is a file containing:",
		"",
		"    [Resolve]",
		"    DNS=127.0.0.1:<dns_port>",
		"    Domains=~<suffix>",
		"",
		"With anything else, consult its documentation for how to send one domain",
		"to one resolver — it has to be able to name a port, which a plain",
		"resolver configuration cannot.",
	}, "\n")
}

func macManual() string {
	return strings.Join([]string{
		"To do this by hand, create /etc/resolver/<suffix> containing:",
		"",
		"    nameserver 127.0.0.1",
		"    port <dns_port>",
	}, "\n")
}
