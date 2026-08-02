package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/identity"
)

// Two servers sharing a pin means they share a keypair. In forward mode that is
// harmless, because each entry dials its own address and the address tells them
// apart. A server that waits to be connected to has no address of its own to
// disambiguate with, so the same pin on two of them makes an inbound peer
// ambiguous, and makes the audit trail ambiguous too: one identity, two
// servers, indistinguishable in a log. Catch it at load rather than at runtime.

func reversePin(t *testing.T) string {
	t.Helper()
	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pin, err := identity.PinForKey(key)
	if err != nil {
		t.Fatalf("PinForKey: %v", err)
	}
	return pin
}

func loadReverseConfig(t *testing.T, body string) (*config.Config, error) {
	t.Helper()
	path := writeConfig(t, body)
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	_, verr := cfg.Validate(config.RoleClient)
	return cfg, verr
}

// TestValidate_DuplicatePinsAcrossListenServers_Rejected is the D4 rule.
func TestValidate_DuplicatePinsAcrossListenServers_Rejected(t *testing.T) {
	pin := reversePin(t)
	_, err := loadReverseConfig(t, `
schema = 1
[servers.alpha]
listen = ":7443"
pin    = "`+pin+`"

[servers.beta]
listen = ":7444"
pin    = "`+pin+`"
`)
	if !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("duplicate pins across listen-mode servers: err = %v, want ErrInvalid", err)
	}
	// The remedy is only actionable if the operator learns which two collided.
	if err == nil || !strings.Contains(err.Error(), "alpha") || !strings.Contains(err.Error(), "beta") {
		t.Errorf("error should name both colliding servers, got: %v", err)
	}
}

// TestValidate_DuplicatePinsAcrossDialServers_Allowed guards the scoping. One
// physical agent serving as two logical named servers with different routes is
// a legitimate existing pattern and must keep working.
func TestValidate_DuplicatePinsAcrossDialServers_Allowed(t *testing.T) {
	pin := reversePin(t)
	_, err := loadReverseConfig(t, `
schema = 1
[servers.alpha]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"

[servers.beta]
addr = "127.0.0.1:7444"
pin  = "`+pin+`"
`)
	if err != nil {
		t.Errorf("duplicate pins across dial-mode servers must stay legal, got: %v", err)
	}
}

// TestValidate_MixedListenAndDialSharedPin_Allowed: only a pair of listen-mode
// servers is ambiguous, because the dial-mode one is told apart by its address.
func TestValidate_MixedListenAndDialSharedPin_Allowed(t *testing.T) {
	pin := reversePin(t)
	_, err := loadReverseConfig(t, `
schema = 1
[servers.alpha]
listen = ":7443"
pin    = "`+pin+`"

[servers.beta]
addr = "127.0.0.1:7444"
pin  = "`+pin+`"
`)
	if err != nil {
		t.Errorf("a listen/dial pair sharing a pin must stay legal, got: %v", err)
	}
}

// TestValidate_ThreeListenServers_NamesTheCollidingPair checks the detection
// identifies which two collide rather than merely noticing that some pin
// repeats somewhere.
func TestValidate_ThreeListenServers_NamesTheCollidingPair(t *testing.T) {
	shared := reversePin(t)
	lone := reversePin(t)
	_, err := loadReverseConfig(t, `
schema = 1
[servers.aaa]
listen = ":7443"
pin    = "`+shared+`"

[servers.bbb]
listen = ":7444"
pin    = "`+lone+`"

[servers.ccc]
listen = ":7445"
pin    = "`+shared+`"
`)
	if !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("want ErrInvalid, got: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "aaa") || !strings.Contains(err.Error(), "ccc") {
		t.Errorf("error should name aaa and ccc, got: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "bbb") {
		t.Errorf("error must not implicate the non-colliding server bbb, got: %v", err)
	}
}

// TestValidate_DisabledListenServer_NotConsideredForDuplicates: a server that
// is never managed cannot collide with anything.
func TestValidate_DisabledListenServer_NotConsideredForDuplicates(t *testing.T) {
	pin := reversePin(t)
	_, err := loadReverseConfig(t, `
schema = 1
[servers.live]
listen = ":7443"
pin    = "`+pin+`"

[servers.off]
listen  = ":7444"
pin     = "`+pin+`"
enabled = false
`)
	if err != nil {
		t.Errorf("a disabled server must not trigger a duplicate-pin error, got: %v", err)
	}
}

// TestValidate_PrivilegedListenPort_AcceptedAtConfigLoad: refusing a privileged
// port is a bind-time concern. The config itself is valid, and on a host that
// has been granted the capability it is usable as written.
func TestValidate_PrivilegedListenPort_AcceptedAtConfigLoad(t *testing.T) {
	pin := reversePin(t)
	_, err := loadReverseConfig(t, `
schema = 1
[servers.rev]
listen = ":443"
pin    = "`+pin+`"
`)
	if err != nil {
		t.Errorf("a privileged listen port must validate; the refusal belongs at bind time, got: %v", err)
	}
}
