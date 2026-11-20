package pairstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mauriciomem/quic-link/internal/atomicfile"
	"github.com/mauriciomem/quic-link/internal/identity"
)

// State is the forensic confirmation state recorded on an authorized_clients
// line. It never affects whether the pin is authorized.
type State int

const (
	StateConfirmed State = iota
	StateUnconfirmed
	StateUnknown // a state= value this version does not know
)

// String returns "confirmed", "unconfirmed" or "unknown".
func (s State) String() string {
	switch s {
	case StateConfirmed:
		return "confirmed"
	case StateUnconfirmed:
		return "unconfirmed"
	default:
		return "unknown"
	}
}

// Entry is one authorized_clients entry.
type Entry struct {
	Pin     string // canonical
	State   State
	Comment string // text after "# ", may be empty
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

// minPrefix is the shortest pin prefix RemoveAuthorized accepts.
const minPrefix = 8

// MalformedError reports why a state file was rejected. Line is 1-based; it
// is 0 when the error is not tied to a line (paired.toml).
type MalformedError struct {
	Path   string
	Line   int
	Reason string
}

func (e *MalformedError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("pairstate: %s:%d: malformed: %s", e.Path, e.Line, e.Reason)
	}
	return fmt.Sprintf("pairstate: %s: malformed: %s", e.Path, e.Reason)
}

// Is reports whether target is ErrMalformed.
func (e *MalformedError) Is(target error) bool { return target == ErrMalformed }

// AmbiguousPrefixError reports a pin prefix matching more than one entry.
// Candidates holds, for each matching pin, its shortest prefix (at least 8
// characters) that no other entry in the file shares.
type AmbiguousPrefixError struct {
	Prefix     string
	Candidates []string
}

func (e *AmbiguousPrefixError) Error() string {
	return fmt.Sprintf("pairstate: pin prefix %q matches %d entries (%s); use a longer prefix",
		e.Prefix, len(e.Candidates), strings.Join(e.Candidates, ", "))
}

// line is one physical line of an authorized_clients file. text excludes the
// LF; terminated reports whether the LF was present. Lines a writer does not
// change are written back from text byte-for-byte.
type line struct {
	text       string
	terminated bool
	entry      *Entry // nil for blank and comment lines
}

// parsedFile is an authorized_clients file split into lines plus the
// deduplicated load result.
type parsedFile struct {
	lines  []line
	result LoadResult
}

// LoadAuthorized reads and parses path. A missing file is an empty result.
// A file with any malformed line is rejected whole with a *MalformedError and
// an empty result.
func LoadAuthorized(path string) (LoadResult, error) {
	pf, err := readAuthorized(path)
	if err != nil {
		return LoadResult{}, err
	}
	return pf.result, nil
}

// LoadAuthorizedAtStart is LoadAuthorized for process start, where there is
// no previously loaded set to fall back to: a malformed file returns an error
// matching both ErrColdStart and the *MalformedError.
func LoadAuthorizedAtStart(path string) (LoadResult, error) {
	res, err := LoadAuthorized(path)
	var me *MalformedError
	if errors.As(err, &me) {
		return LoadResult{}, fmt.Errorf("%w: %w", ErrColdStart, me)
	}
	return res, err
}

// Allowed returns the set of authorized pins: every entry, whatever its
// state. It is the only way to build the set and it never filters.
func Allowed(r LoadResult) map[string]struct{} {
	set := make(map[string]struct{}, len(r.Entries))
	for _, e := range r.Entries {
		set[e.Pin] = struct{}{}
	}
	return set
}

// readAuthorized reads path without locking; a missing file parses as empty.
func readAuthorized(path string) (parsedFile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return parsedFile{}, nil
	}
	if err != nil {
		return parsedFile{}, fmt.Errorf("pairstate: read %s: %w", path, err)
	}
	return parseAuthorized(path, string(data))
}

// parseAuthorized parses a whole file. Duplicate pins are deduplicated, the
// first line winning; notes are reported for every line.
func parseAuthorized(path, data string) (parsedFile, error) {
	var pf parsedFile
	seen := make(map[string]bool)
	for i, seg := range strings.SplitAfter(data, "\n") {
		if seg == "" {
			continue // after a final LF
		}
		l := line{text: strings.TrimSuffix(seg, "\n"), terminated: strings.HasSuffix(seg, "\n")}
		entry, notes, reason := parseLine(l.text)
		if reason != "" {
			return parsedFile{}, &MalformedError{Path: path, Line: i + 1, Reason: reason}
		}
		for _, tok := range notes {
			pf.result.Notes = append(pf.result.Notes, Note{Line: i + 1, Token: tok})
		}
		if entry != nil {
			l.entry = entry
			if !seen[entry.Pin] {
				seen[entry.Pin] = true
				pf.result.Entries = append(pf.result.Entries, *entry)
			}
		}
		pf.lines = append(pf.lines, l)
	}
	return pf, nil
}

// isWSP reports whether b separates fields. Only space and tab do: \v, \f
// and non-ASCII spaces stay inside a field, so a pin carrying them fails the
// strict pin check instead of being silently trimmed.
func isWSP(b byte) bool { return b == ' ' || b == '\t' }

// isText reports whether b may appear in comment text: printable ASCII or tab.
func isText(b byte) bool { return b == '\t' || (b >= 0x20 && b <= 0x7e) }

// isTokenByte reports whether b may appear in a tag token.
func isTokenByte(b byte) bool { return b >= 0x21 && b <= 0x7e && b != '#' }

// parseLine parses one line (without its LF). It returns the entry (nil for
// blank and comment lines), the ignored tokens, and a non-empty reason when
// the line is malformed.
func parseLine(s string) (entry *Entry, notes []string, reason string) {
	if strings.HasSuffix(s, "\r") {
		return nil, nil, "CRLF line ending; lines must end with LF only"
	}
	i := skipWSP(s, 0)
	if i == len(s) {
		return nil, nil, ""
	}
	if s[i] == '#' {
		if !validText(s[i+1:]) {
			return nil, nil, "comment contains a control or non-ASCII character"
		}
		return nil, nil, ""
	}
	field, i := nextField(s, i)
	pin, err := identity.ParsePinStrict(field)
	if err != nil {
		return nil, nil, fmt.Sprintf("invalid pin field %q: %v", field, err)
	}
	e := &Entry{Pin: pin, State: StateConfirmed}
	sawState := false
	for i = skipWSP(s, i); i < len(s); i = skipWSP(s, i) {
		if s[i] == '#' {
			comment := strings.TrimPrefix(s[i+1:], " ")
			if !validText(comment) {
				return nil, nil, "comment contains a control or non-ASCII character"
			}
			e.Comment = comment
			break
		}
		var tok string
		tok, i = nextField(s, i)
		if !validToken(tok) {
			return nil, nil, fmt.Sprintf("invalid token %q", tok)
		}
		value, isState := strings.CutPrefix(tok, "state=")
		if !isState {
			notes = append(notes, tok)
			continue
		}
		if sawState {
			return nil, nil, "more than one state= token"
		}
		sawState = true
		switch value {
		case "confirmed":
			e.State = StateConfirmed
		case "unconfirmed":
			e.State = StateUnconfirmed
		default:
			e.State = StateUnknown
			notes = append(notes, tok)
		}
	}
	return e, notes, ""
}

func skipWSP(s string, i int) int {
	for i < len(s) && isWSP(s[i]) {
		i++
	}
	return i
}

// nextField returns the field starting at i and the index just past it.
func nextField(s string, i int) (string, int) {
	j := i
	for j < len(s) && !isWSP(s[j]) {
		j++
	}
	return s[i:j], j
}

func validText(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isText(s[i]) {
			return false
		}
	}
	return true
}

func validToken(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isTokenByte(s[i]) {
			return false
		}
	}
	return s != ""
}

// formatLine renders e exactly as writers emit it: "PIN state=<v>" or
// "PIN state=<v> # <comment>".
func formatLine(e Entry) string {
	s := e.Pin + " state=" + e.State.String()
	if e.Comment != "" {
		s += " # " + e.Comment
	}
	return s
}

// render joins lines back into file content. A writer that adds a line after
// an unterminated last line terminates it first; other lines are unchanged.
func render(lines []line) []byte {
	var b strings.Builder
	for i, l := range lines {
		b.WriteString(l.text)
		if l.terminated || i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return []byte(b.String())
}

// validateEntry checks an entry a caller asks to append.
func validateEntry(e Entry) error {
	if _, err := identity.ParsePinStrict(e.Pin); err != nil {
		return fmt.Errorf("pairstate: invalid pin %q: %w", e.Pin, err)
	}
	if e.State != StateConfirmed && e.State != StateUnconfirmed {
		return fmt.Errorf("pairstate: cannot write state %d; want confirmed or unconfirmed", int(e.State))
	}
	if !validText(e.Comment) {
		return fmt.Errorf("pairstate: comment %q contains a control or non-ASCII character", e.Comment)
	}
	return nil
}

// AppendAuthorized adds e as "PIN state=<v>[ # <comment>]". A pin already
// present returns (false, nil) and leaves the file untouched, so an existing
// entry is never downgraded. It holds the authorized_clients lock (see
// withLock).
func AppendAuthorized(path string, e Entry) (bool, error) {
	return appendAuthorizedWith(defaultLockOpts(), path, e)
}

// RemoveAuthorized removes every line carrying the one pin that pinPrefix
// (at least 8 characters) selects, and returns that entry. It holds the
// authorized_clients lock (see withLock).
func RemoveAuthorized(path, pinPrefix string) (Entry, error) {
	return removeAuthorizedWith(defaultLockOpts(), path, pinPrefix)
}

// PromoteAuthorized marks pin confirmed. An absent pin returns ErrNotFound and
// is never re-added, so a promote racing a removal cannot resurrect it. It
// holds the authorized_clients lock (see withLock).
func PromoteAuthorized(path, pin string) error {
	return promoteAuthorizedWith(defaultLockOpts(), path, pin)
}

func appendAuthorizedWith(o lockOpts, path string, e Entry) (bool, error) {
	if err := validateEntry(e); err != nil {
		return false, err
	}
	added := false
	err := withLock(o, path, func() error {
		pf, err := readAuthorized(path)
		if err != nil {
			return err
		}
		for _, have := range pf.result.Entries {
			if have.Pin == e.Pin {
				return nil
			}
		}
		lines := append(pf.lines, line{text: formatLine(e), terminated: true})
		if err := atomicfile.Write(path, render(lines), 0o600); err != nil {
			return fmt.Errorf("pairstate: write %s: %w", path, err)
		}
		added = true
		return nil
	})
	return added, err
}

func removeAuthorizedWith(o lockOpts, path, pinPrefix string) (Entry, error) {
	if len(pinPrefix) < minPrefix {
		return Entry{}, ErrPrefixShort
	}
	var removed Entry
	err := withLock(o, path, func() error {
		pf, err := readAuthorized(path)
		if err != nil {
			return err
		}
		var matches []Entry
		for _, e := range pf.result.Entries {
			if strings.HasPrefix(e.Pin, pinPrefix) {
				matches = append(matches, e)
			}
		}
		switch {
		case len(matches) == 0:
			return ErrNotFound
		case len(matches) > 1:
			return &AmbiguousPrefixError{Prefix: pinPrefix, Candidates: candidates(matches, pf.result.Entries)}
		}
		removed = matches[0]
		kept := make([]line, 0, len(pf.lines))
		for _, l := range pf.lines {
			if l.entry == nil || l.entry.Pin != removed.Pin {
				kept = append(kept, l)
			}
		}
		if err := atomicfile.Write(path, render(kept), 0o600); err != nil {
			return fmt.Errorf("pairstate: write %s: %w", path, err)
		}
		return nil
	})
	if err != nil {
		return Entry{}, err
	}
	return removed, nil
}

// candidates returns, for each match, its shortest prefix of at least
// minPrefix characters that no other entry shares.
func candidates(matches, all []Entry) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		n := minPrefix
		for n < len(m.Pin) && sharesPrefix(m.Pin[:n], m.Pin, all) {
			n++
		}
		out = append(out, m.Pin[:n])
	}
	return out
}

func sharesPrefix(prefix, self string, all []Entry) bool {
	for _, e := range all {
		if e.Pin != self && strings.HasPrefix(e.Pin, prefix) {
			return true
		}
	}
	return false
}

func promoteAuthorizedWith(o lockOpts, path, pin string) error {
	return withLock(o, path, func() error {
		pf, err := readAuthorized(path)
		if err != nil {
			return err
		}
		var current *Entry
		for i := range pf.result.Entries {
			if pf.result.Entries[i].Pin == pin {
				current = &pf.result.Entries[i]
				break
			}
		}
		if current == nil {
			return ErrNotFound
		}
		if current.State == StateConfirmed {
			return nil
		}
		for i, l := range pf.lines {
			if l.entry != nil && l.entry.Pin == pin && l.entry.State != StateConfirmed {
				promoted := Entry{Pin: pin, State: StateConfirmed, Comment: l.entry.Comment}
				pf.lines[i] = line{text: formatLine(promoted), terminated: l.terminated, entry: &promoted}
			}
		}
		if err := atomicfile.Write(path, render(pf.lines), 0o600); err != nil {
			return fmt.Errorf("pairstate: write %s: %w", path, err)
		}
		return nil
	})
}

// lockOpts controls how long a writer waits for the exclusive lock.
type lockOpts struct {
	timeout  time.Duration
	interval time.Duration
}

// defaultLockOpts is what the exported writers use: try every 10 ms for 5 s.
func defaultLockOpts() lockOpts {
	return lockOpts{timeout: 5 * time.Second, interval: 10 * time.Millisecond}
}

// withLock runs fn while holding an exclusive flock on path+".lock", which is
// created 0600 (parent 0700) on first use and never deleted. The lock is
// taken with LOCK_NB and retried every o.interval until o.timeout, then
// ErrLockTimeout is returned without running fn.
//
// The lock is advisory: it only serializes writers that take it, all running
// as the same user. A hand edit of authorized_clients bypasses it. Lock
// behavior on NFS, FUSE and other network or userspace filesystems is
// untested and unsupported; keep the state directory on a local filesystem.
func withLock(o lockOpts, path string, fn func() error) (err error) {
	lockPath := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return fmt.Errorf("pairstate: create dir for %s: %w", lockPath, err)
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("pairstate: open lock %s: %w", lockPath, err)
	}
	defer func() {
		// Closing the descriptor releases the flock.
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("pairstate: close lock %s: %w", lockPath, cerr)
		}
	}()
	if err := acquire(o, int(f.Fd())); err != nil {
		return fmt.Errorf("%w (lock file %s)", err, lockPath)
	}
	return fn()
}

// acquire takes LOCK_EX on fd, polling without blocking so the wait is
// bounded and leaves no goroutine or timer behind. It returns ErrLockTimeout
// once o.timeout has passed with the lock still held elsewhere.
func acquire(o lockOpts, fd int) error {
	deadline := time.Now().Add(o.timeout)
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return fmt.Errorf("pairstate: flock: %w", err)
		}
		if !time.Now().Before(deadline) {
			return ErrLockTimeout
		}
		time.Sleep(o.interval)
	}
}
