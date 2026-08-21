package main

// Reverse mode used to be refused everywhere. Now that a server can be
// configured to wait for its agent to connect, what these tests cover is that
// the refusal is gone and that the failures which remain are the ones an
// operator can actually act on: an address that cannot be parsed, one already
// taken, and one that needs privileges this process does not have.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func reverseServerConfig(t *testing.T, listen string) string {
	t.Helper()
	pin := mustTestPin(t)
	// The identity is named explicitly rather than left to the default path
	// under the invoking user's home. Without it these tests found whatever key
	// the machine they ran on happened to have, and reported the state of that
	// machine's setup instead of the thing they were written to check — a
	// developer with no key saw them fail for a reason unrelated to any of them.
	key := writeTestKey(t)
	return writeTestConfig(t, `
schema = 1
[identity]
key_file = "`+key+`"
[servers.rev]
listen = "`+listen+`"
pin    = "`+pin+`"
`)
}

// runDaemonBriefly starts the daemon and cancels it shortly after, so a config
// that is accepted does not block the test. Startup failures return before the
// cancellation ever matters.
//
// It gives the daemon a socket directory of its own. The single-instance check
// runs before any address is bound, so without isolation a daemon already
// running for real on the same machine answers first and every one of these
// tests reports that instead of the thing it is actually checking.
func runDaemonBriefly(t *testing.T, args ...string) error {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", shortTempDir(t))
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	return runVerbCtx(ctx, args)
}

// TestDaemon_ReverseServer_NoLongerRefused covers both spellings. Neither may
// still answer with the old "not yet supported" refusal.
func TestDaemon_ReverseServer_NoLongerRefused(t *testing.T) {
	unsetQLEnvForTest(t)

	tests := []struct {
		name string
		args func(cfg string) []string
	}{
		{"unscoped", func(cfg string) []string { return []string{"--config", cfg, "daemon"} }},
		{"scoped", func(cfg string) []string { return []string{"--config", cfg, "daemon", "--server", "rev"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := reverseServerConfig(t, "127.0.0.1:0")
			err := runDaemonBriefly(t, tt.args(path)...)
			if err != nil && strings.Contains(err.Error(), "not yet supported") {
				t.Errorf("daemon still refuses a reverse-mode server: %v", err)
			}
		})
	}
}

// TestDaemon_MalformedListenAddress_Exit2 keeps an unparseable address a usage
// error rather than something that surfaces later as a bind failure.
func TestDaemon_MalformedListenAddress_Exit2(t *testing.T) {
	unsetQLEnvForTest(t)
	path := reverseServerConfig(t, "not-an-address")

	err := runDaemonBriefly(t, "--config", path, "daemon")
	if exitCode(err) != 2 {
		t.Errorf("malformed listen address: want exit 2, got %d: %v", exitCode(err), err)
	}
}

// TestDaemon_ListenAddressInUse_Exit2 names the conflict instead of failing
// with a bare errno.
func TestDaemon_ListenAddressInUse_Exit2(t *testing.T) {
	unsetQLEnvForTest(t)

	held, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("hold a port: %v", err)
	}
	defer held.Close()

	path := reverseServerConfig(t, held.LocalAddr().String())
	err = runDaemonBriefly(t, "--config", path, "daemon")
	if exitCode(err) != 2 {
		t.Errorf("listen address in use: want exit 2, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("error should say the address is in use, got: %v", err)
	}
}

// TestDaemon_PrivilegedListenPort_Exit2_NeverMentionsSudo is the one that
// matters for how a user reacts. Telling someone a bind needs privileges, with
// no alternative offered, invites them to rerun the whole daemon as root, which
// puts the long-lived identity key inside a privileged process to solve a
// problem a different port also solves.
func TestDaemon_PrivilegedListenPort_Exit2_NeverMentionsSudo(t *testing.T) {
	unsetQLEnvForTest(t)
	if os.Geteuid() == 0 {
		t.Skip("running as root: a privileged port would bind successfully")
	}

	path := reverseServerConfig(t, "127.0.0.1:80")
	err := runDaemonBriefly(t, "--config", path, "daemon")

	if exitCode(err) != 2 {
		t.Fatalf("privileged listen port: want exit 2, got %d: %v", exitCode(err), err)
	}
	msg := strings.ToLower(err.Error())
	for _, forbidden := range []string{"sudo", "root", "elevat"} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("message must not suggest escalating privileges, but mentions %q: %v",
				forbidden, err)
		}
	}
	if !strings.Contains(msg, "1024") {
		t.Errorf("message should point at a usable port range, got: %v", err)
	}
}

// TestClassifyListenBindError_UsesErrnoNotString: bind failures are classified
// by error value. The text of an OS error is not a stable thing to match on,
// and this project has been caught by string-matched classification before.
func TestClassifyListenBindError_UsesErrnoNotString(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantExit int
		wantMsg  string
	}{
		{
			name:     "address in use",
			err:      &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)},
			wantExit: 2,
			wantMsg:  "in use",
		},
		{
			name:     "permission denied",
			err:      &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EACCES)},
			wantExit: 2,
			wantMsg:  "1024",
		},
		{
			name:     "anything else stays a plain failure",
			err:      errors.New("some other problem"),
			wantExit: 1,
			wantMsg:  "some other problem",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyListenBindError("rev", ":7443", tt.err)
			if exitCode(got) != tt.wantExit {
				t.Errorf("exit = %d, want %d: %v", exitCode(got), tt.wantExit, got)
			}
			if !strings.Contains(got.Error(), tt.wantMsg) {
				t.Errorf("message %q should contain %q", got, tt.wantMsg)
			}
			if !strings.Contains(got.Error(), "rev") {
				t.Errorf("message should name the server, got: %v", got)
			}
		})
	}
}

// TestClassifyListenBindError_WrappedErrnoStillClassified: the errno arrives
// wrapped in layers by the net package, so the check has to unwrap rather than
// compare against the top-level error.
func TestClassifyListenBindError_WrappedErrnoStillClassified(t *testing.T) {
	deep := fmt.Errorf("outer: %w", &net.OpError{
		Op:  "listen",
		Err: os.NewSyscallError("bind", syscall.EACCES),
	})
	got := classifyListenBindError("rev", ":80", deep)
	if exitCode(got) != 2 {
		t.Errorf("a wrapped permission error should still be a usage error, got %d: %v",
			exitCode(got), got)
	}
}
