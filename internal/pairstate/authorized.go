package pairstate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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

// Note reports something on a line that was ignored or tolerated. Token and
// Reason are always printable ASCII: text taken from the file is escaped.
type Note struct {
	Line   int    // 1-based
	Token  string // what Reason is about; "" for a CRLF line ending
	Reason string // one of the fixed reason texts, such as "unknown tag"
}

// LoadResult is the parsed content of an authorized_clients file.
//
// Note.Token, Note.Reason and the text of every *MalformedError for
// authorized_clients contain only bytes 0x20-0x7E; Entry.Comment contains
// only those bytes and tab. MalformedError.Path is the caller's path and is
// printed as given.
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
	ErrUnsafePath  = errors.New("pairstate: refusing an unsafe state path")
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
// A file in which any line's pin field does not parse, or a file larger than
// 1 MiB, is rejected whole with a *MalformedError and an empty result.
//
// Every exported function of this package that takes a state path requires
// it to be absolute and clean (filepath.Clean(path) == path); any other path
// is refused with ErrUnsafePath before the file system is touched.
func LoadAuthorized(path string) (LoadResult, error) {
	if err := checkStatePathSyntax(path); err != nil {
		return LoadResult{}, err
	}
	pf, err := readAuthorized(path)
	if err != nil {
		return LoadResult{}, err
	}
	return pf.result, nil
}

// LoadAuthorizedAtStart is LoadAuthorized for process start, where there is
// no previously loaded set to fall back to: a malformed file returns an error
// matching both ErrColdStart and the *MalformedError. An unsafe path is
// returned as the ErrUnsafePath error, without ErrColdStart.
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

// readAuthorized reads path without locking; a missing directory or file
// parses as empty. The directory and the file are checked first (see
// checkPrivate), then the opened file again (see readStateFile).
func readAuthorized(path string) (parsedFile, error) {
	exists, err := verifyStatePath(path)
	if err != nil || !exists {
		return parsedFile{}, err
	}
	data, err := readStateFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return parsedFile{}, nil
	}
	if err != nil {
		return parsedFile{}, err
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
		for _, n := range notes {
			pf.result.Notes = append(pf.result.Notes, Note{Line: i + 1, Token: n.token, Reason: n.reason})
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

// Note reasons. They are fixed texts so callers can match them.
const (
	reasonUnknownTag     = "unknown tag"
	reasonUnknownState   = "unknown state value"
	reasonDuplicateState = "duplicate state tag"
	reasonMalformedTag   = "malformed tag"
	reasonCommentText    = "comment with control or non-ASCII characters"
	reasonCRLF           = "CRLF line ending"
)

// lineNote is a Note before its line number is known.
type lineNote struct {
	token  string
	reason string
}

// parseLine parses one line (without its LF). It returns the entry (nil for
// blank and comment lines) and the notes for what it tolerated. A non-empty
// reason means the pin field does not parse, the only thing that makes a
// line malformed; the entry and notes are then meaningless.
func parseLine(s string) (entry *Entry, notes []lineNote, reason string) {
	if trimmed, crlf := strings.CutSuffix(s, "\r"); crlf {
		s = trimmed
		notes = append(notes, lineNote{reason: reasonCRLF})
	}
	i := skipWSP(s, 0)
	if i == len(s) {
		return nil, notes, ""
	}
	if s[i] == '#' {
		if text := strings.TrimPrefix(s[i+1:], " "); !validText(text) {
			notes = append(notes, lineNote{strconv.QuoteToASCII(text), reasonCommentText})
		}
		return nil, notes, ""
	}
	field, i := nextField(s, i)
	pin, err := identity.ParsePinStrict(field)
	if err != nil {
		return nil, nil, fmt.Sprintf("invalid pin field %+q: %v", field, err)
	}
	e := &Entry{Pin: pin, State: StateConfirmed}
	sawState := false
	for i = skipWSP(s, i); i < len(s); i = skipWSP(s, i) {
		if s[i] == '#' {
			text := strings.TrimPrefix(s[i+1:], " ")
			e.Comment = text
			if !validText(text) {
				e.Comment = escapeText(text)
				notes = append(notes, lineNote{strconv.QuoteToASCII(text), reasonCommentText})
			}
			break
		}
		var tok string
		tok, i = nextField(s, i)
		if !validToken(tok) {
			notes = append(notes, lineNote{strconv.QuoteToASCII(tok), reasonMalformedTag})
			continue
		}
		value, isState := strings.CutPrefix(tok, "state=")
		switch {
		case !isState:
			notes = append(notes, lineNote{tok, reasonUnknownTag})
			continue
		case sawState:
			notes = append(notes, lineNote{tok, reasonDuplicateState})
			continue
		}
		sawState = true
		switch value {
		case "confirmed":
			e.State = StateConfirmed
		case "unconfirmed":
			e.State = StateUnconfirmed
		default:
			e.State = StateUnknown
			notes = append(notes, lineNote{tok, reasonUnknownState})
		}
	}
	return e, notes, ""
}

// escapeText makes s comment text: printable ASCII and tab are kept, an
// invalid UTF-8 byte becomes \xNN and any other rune its Go escape (\x1b,
// \u00e9, \U0001f600). It is safe to display but not reversible: a literal
// backslash is kept as is.
func escapeText(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case size == 1 && isText(s[0]):
			b.WriteByte(s[0])
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[0])
		default:
			q := strconv.QuoteRuneToASCII(r)
			b.WriteString(q[1 : len(q)-1])
		}
		s = s[size:]
	}
	return b.String()
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
// is never re-added, so a promote racing a removal cannot resurrect it. Each
// line carrying the pin is rewritten as "PIN state=confirmed[ # comment]";
// other tags on it are dropped and a non-ASCII comment is kept in its escaped
// form. It holds the authorized_clients lock (see withLock).
func PromoteAuthorized(path, pin string) error {
	return promoteAuthorizedWith(defaultLockOpts(), path, pin)
}

func appendAuthorizedWith(o lockOpts, path string, e Entry) (bool, error) {
	if err := checkStatePathSyntax(path); err != nil {
		return false, err
	}
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
	if err := checkStatePathSyntax(path); err != nil {
		return Entry{}, err
	}
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
	if err := checkStatePathSyntax(path); err != nil {
		return err
	}
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
//
// State files, their directory and the lock file must be owned by the current
// user and not writable by group or others, and must not be symbolic links;
// the lock file must also not be readable by group or others (see
// checkLock). Otherwise every operation fails with ErrUnsafePath; the lock is
// never re-moded. The directory is checked
// before the lock is opened, and the lock is opened without following a
// symbolic link and then checked on its open descriptor.
func withLock(o lockOpts, path string, fn func() error) (err error) {
	lockPath := path + ".lock"
	dir := filepath.Dir(lockPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("pairstate: create dir for %s: %w", lockPath, err)
	}
	if exists, err := verifyStateDir(dir); err != nil {
		return err
	} else if !exists {
		return fmt.Errorf("pairstate: state directory %s vanished after it was created", dir)
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if errors.Is(err, unix.ELOOP) {
		return unsafePath(lockPath, "is a symbolic link")
	}
	if err != nil {
		return fmt.Errorf("pairstate: open lock %s: %w", lockPath, err)
	}
	defer func() {
		// Closing the descriptor releases the flock.
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("pairstate: close lock %s: %w", lockPath, cerr)
		}
	}()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("pairstate: stat lock %s: %w", lockPath, err)
	}
	if err := checkLock(lockPath, fi, os.Geteuid()); err != nil {
		return err
	}
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
