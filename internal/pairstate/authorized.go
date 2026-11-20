package pairstate

import (
	"errors"
	"time"
)

// errNotImplemented is returned by every stub until the package is implemented.
var errNotImplemented = errors.New("pairstate: not implemented")

// State is the forensic confirmation state recorded on an authorized_clients line.
type State int

const (
	StateConfirmed State = iota
	StateUnconfirmed
	StateUnknown
)

// String returns "confirmed", "unconfirmed" or "unknown".
func (s State) String() string { return "" }

// Entry is one authorized_clients entry.
type Entry struct {
	Pin     string
	State   State
	Comment string
}

// Note reports a token that was ignored on a line.
type Note struct {
	Line  int
	Token string
}

// LoadResult is the parsed content of an authorized_clients file.
type LoadResult struct {
	Entries []Entry
	Notes   []Note
}

var (
	ErrMalformed   = errors.New("pairstate: authorized_clients is malformed")
	ErrNotFound    = errors.New("pairstate: no matching authorized pin")
	ErrPrefixShort = errors.New("pairstate: pin prefix must be at least 8 characters")
	ErrLockTimeout = errors.New("pairstate: timed out waiting for the authorized_clients lock")
	ErrColdStart   = errors.New("pairstate: authorized_clients is malformed at startup")
)

// MalformedError reports why a state file was rejected.
type MalformedError struct {
	Path   string
	Line   int
	Reason string
}

func (e *MalformedError) Error() string { return "not implemented" }

// Is reports whether target is ErrMalformed.
func (e *MalformedError) Is(target error) bool { return false }

// AmbiguousPrefixError reports a pin prefix matching more than one entry.
type AmbiguousPrefixError struct {
	Prefix     string
	Candidates []string
}

func (e *AmbiguousPrefixError) Error() string { return "not implemented" }

// lockOpts controls how long a writer waits for the exclusive lock.
type lockOpts struct {
	timeout  time.Duration
	interval time.Duration
}

func defaultLockOpts() lockOpts { return lockOpts{} }

func LoadAuthorized(path string) (LoadResult, error) { return LoadResult{}, errNotImplemented }

func LoadAuthorizedAtStart(path string) (LoadResult, error) {
	return LoadResult{}, errNotImplemented
}

func Allowed(r LoadResult) map[string]struct{} { return map[string]struct{}{} }

func AppendAuthorized(path string, e Entry) (bool, error) {
	return appendAuthorizedWith(defaultLockOpts(), path, e)
}

func RemoveAuthorized(path, pinPrefix string) (Entry, error) {
	return removeAuthorizedWith(defaultLockOpts(), path, pinPrefix)
}

func PromoteAuthorized(path, pin string) error {
	return promoteAuthorizedWith(defaultLockOpts(), path, pin)
}

func appendAuthorizedWith(o lockOpts, path string, e Entry) (bool, error) {
	return false, errNotImplemented
}

func removeAuthorizedWith(o lockOpts, path, pinPrefix string) (Entry, error) {
	return Entry{}, errNotImplemented
}

func promoteAuthorizedWith(o lockOpts, path, pin string) error { return errNotImplemented }
