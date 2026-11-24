/**
 * @spec-handoff
 * @interface type AuthorizedPersister struct{ Path string; Now func() time.Time }  // Now nil -> time.Now
 * @interface (*AuthorizedPersister).Persist(pin, label string, from netip.AddrPort) error; (*AuthorizedPersister).Confirm(pin string) error  // pairing.Persister + pairing.Confirmer
 * @behavior
 *   - Persist = AppendAuthorized(Path, Entry{pin, StateUnconfirmed, `label="<label>" from=<from> at=<Now() RFC3339>`}) -> line `PIN state=unconfirmed # label="laptop" from=192.0.2.7:4433 at=2026-11-22T10:00:00Z`
 *   - Persist of a pin already present is nil and leaves the file untouched (never downgrades a confirmed entry)
 *   - Confirm = PromoteAuthorized(Path, pin): the line becomes `PIN state=confirmed # <same comment>`; again is nil; an absent pin is ErrNotFound
 *   - Errors pass through: invalid pin, unsafe or unclean Path (ErrUnsafePath)
 * @edge-cases
 *   - Label quoting beyond a plain label is not pinned here (Go %q is the natural choice; the pairing label never holds '#')
 * @see ./holder.go ./authorized.go ../pairing/serve.go
 */

package pairstate

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// persisterContract is the pairing handler's Persister and Confirmer.
type persisterContract interface {
	Persist(pin, label string, from netip.AddrPort) error
	Confirm(pin string) error
}

var _ persisterContract = (*AuthorizedPersister)(nil)

func TestAuthorizedPersister_AppendsUnconfirmedThenConfirms(t *testing.T) {
	a, b := testPin("persist-a"), testPin("persist-b")
	at := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	from4 := netip.MustParseAddrPort("192.0.2.7:4433")
	from6 := netip.MustParseAddrPort("[2001:db8::1]:51000")
	lineA := a + ` state=unconfirmed # label="laptop" from=192.0.2.7:4433 at=2026-11-22T10:00:00Z` + "\n"
	lineB := b + ` state=unconfirmed # label="phone" from=[2001:db8::1]:51000 at=2026-11-22T10:00:00Z` + "\n"
	confirmedA := a + ` state=confirmed # label="laptop" from=192.0.2.7:4433 at=2026-11-22T10:00:00Z` + "\n"

	_, path := holderDir(t)
	per := &AuthorizedPersister{Path: path, Now: func() time.Time { return at }}

	if err := per.Persist(a, "laptop", from4); err != nil {
		t.Fatalf("Persist = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Persist wrote nothing: %v", err)
	}
	if got := readRaw(t, path); got != lineA {
		t.Errorf("after Persist the file is %q, want %q", got, lineA)
	}
	assertMode(t, path, 0o600)
	res, err := LoadAuthorized(path)
	if err != nil || len(res.Entries) != 1 || res.Entries[0].State != StateUnconfirmed || len(res.Notes) != 0 {
		t.Errorf("LoadAuthorized = (%+v, %v), want one unconfirmed entry and no notes", res, err)
	}

	if err := per.Persist(a, "other-label", from6); err != nil {
		t.Errorf("Persist of a present pin = %v, want nil", err)
	}
	if got := readRaw(t, path); got != lineA {
		t.Errorf("Persist of a present pin changed the file to %q", got)
	}

	if err := per.Persist(b, "phone", from6); err != nil {
		t.Fatalf("Persist(b) = %v", err)
	}
	if got := readRaw(t, path); got != lineA+lineB {
		t.Errorf("after the second Persist the file is %q, want %q", got, lineA+lineB)
	}

	if err := per.Confirm(a); err != nil {
		t.Fatalf("Confirm = %v", err)
	}
	if got := readRaw(t, path); got != confirmedA+lineB {
		t.Errorf("after Confirm the file is %q, want %q", got, confirmedA+lineB)
	}
	if err := per.Confirm(a); err != nil {
		t.Errorf("Confirm again = %v, want nil", err)
	}
	if err := per.Persist(a, "laptop", from4); err != nil {
		t.Errorf("Persist of a confirmed pin = %v, want nil", err)
	}
	if got := readRaw(t, path); got != confirmedA+lineB {
		t.Errorf("Confirm again / Persist of a confirmed pin changed the file to %q", got)
	}
	if err := per.Confirm(testPin("persist-absent")); !errors.Is(err, ErrNotFound) {
		t.Errorf("Confirm of an absent pin = %v, want ErrNotFound", err)
	}

	t.Run("nil Now uses the wall clock", func(t *testing.T) {
		_, path := holderDir(t)
		per := &AuthorizedPersister{Path: path}
		before := time.Now().Truncate(time.Second)
		if err := per.Persist(a, "laptop", from4); err != nil {
			t.Fatalf("Persist = %v", err)
		}
		after := time.Now()
		_, stamp, ok := strings.Cut(strings.TrimSuffix(readRaw(t, path), "\n"), " at=")
		if !ok {
			t.Fatalf("file %q has no at= field", readRaw(t, path))
		}
		got, err := time.Parse(time.RFC3339, stamp)
		if err != nil || got.Before(before) || got.After(after) {
			t.Errorf("at=%q (%v), want an RFC 3339 time between %v and %v", stamp, err, before, after)
		}
	})

	t.Run("errors pass through", func(t *testing.T) {
		dir, path := holderDir(t)
		per := &AuthorizedPersister{Path: path, Now: func() time.Time { return at }}
		if err := per.Persist("not-a-pin", "laptop", from4); err == nil {
			t.Error("Persist of an invalid pin = nil, want an error")
		}
		assertAbsent(t, path)
		mustDo(t, os.Chmod(dir, 0o777))
		if err := per.Persist(a, "laptop", from4); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("Persist into a 0777 directory = %v, want ErrUnsafePath", err)
		}
		mustDo(t, os.Chmod(dir, 0o700))
		unclean := &AuthorizedPersister{Path: filepath.Join(dir, "sub") + "/../authorized_clients", Now: per.Now}
		mustDo(t, os.Mkdir(filepath.Join(dir, "sub"), 0o700))
		if err := unclean.Persist(a, "laptop", from4); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("Persist with an unclean path = %v, want ErrUnsafePath", err)
		}
		if err := unclean.Confirm(a); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("Confirm with an unclean path = %v, want ErrUnsafePath", err)
		}
	})
}
