/**
 * @spec-handoff
 * @interface LoadAuthorized(path string) (LoadResult, error); LoadAuthorizedAtStart(path string) (LoadResult, error); Allowed(LoadResult) map[string]struct{}
 * @interface AppendAuthorized(path string, e Entry) (added bool, err error); RemoveAuthorized(path, pinPrefix string) (Entry, error); PromoteAuthorized(path, pin string) error
 * @behavior
 *   - Line = blank | "#"-comment | PIN *(1*WSP token) [1*WSP "#" text]; WSP is SP/HTAB only; LF-terminated; Comment = text after "# "
 *   - PIN must equal identity.ParsePinStrict(PIN) - nothing is trimmed first; a bad pin rejects the whole file: *MalformedError{Path, Line}, errors.Is ErrMalformed, empty result
 *   - no state= -> StateConfirmed; state=unconfirmed/confirmed; unknown state= value -> StateUnknown + Note{Line, Token}; other tokens ignored + Note
 *   - duplicate state= tokens and CRLF -> malformed; a pin listed twice is deduped (first line wins)
 *   - Allowed includes every entry of every state; the package doc says no tag may restrict access and revocation is deleting the line
 *   - Writers emit exactly "PIN state=<v>" or "PIN state=<v> # <comment>" + LF, keep every other line byte-for-byte, write 0600, dir 0700
 *   - Append: strict pin, state confirmed|unconfirmed, comment in %x20-7E/HTAB; present pin -> (false, nil), file untouched
 *   - Remove: prefix < 8 -> ErrPrefixShort; >1 match -> *AmbiguousPrefixError; none -> ErrNotFound; removes that line only
 *   - Promote: absent -> ErrNotFound (never re-adds); already confirmed -> nil, untouched; writers refuse a malformed file
 * @see ./authorized.go
 */

package pairstate

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func loadString(t *testing.T, content string) (LoadResult, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authorized_clients")
	writeRaw(t, path, content)
	return LoadAuthorized(path)
}

// assertMalformed checks err is a *MalformedError for path and line that also
// matches ErrMalformed, and that no partial result leaked out.
func assertMalformed(t *testing.T, res LoadResult, err error, path string, line int) {
	t.Helper()
	var me *MalformedError
	if !errors.As(err, &me) {
		t.Fatalf("err = %v, want *MalformedError", err)
	}
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("errors.Is(err, ErrMalformed) = false for %v", err)
	}
	if path != "" && me.Path != path {
		t.Errorf("MalformedError.Path = %q, want %q", me.Path, path)
	}
	if me.Line != line {
		t.Errorf("MalformedError.Line = %d, want %d", me.Line, line)
	}
	if me.Reason == "" {
		t.Errorf("MalformedError.Reason is empty")
	}
	if len(res.Entries) != 0 || len(res.Notes) != 0 {
		t.Errorf("malformed file returned a partial result: %+v", res)
	}
}

func TestParseAuthorizedLine_Grammar(t *testing.T) {
	p := testPin("grammar-a")
	q := testPin("grammar-b")

	valid := []struct {
		name    string
		content string
		entries []Entry
		notes   []Note
	}{
		{"bare pin is confirmed", p + "\n", []Entry{{Pin: p, State: StateConfirmed}}, nil},
		{"explicit confirmed", p + " state=confirmed\n", []Entry{{Pin: p, State: StateConfirmed}}, nil},
		{"unconfirmed with comment", p + " state=unconfirmed # laptop\n",
			[]Entry{{Pin: p, State: StateUnconfirmed, Comment: "laptop"}}, nil},
		{"comment keeps key=value text verbatim", p + ` state=unconfirmed # label="laptop" from=192.0.2.7:51000 at=2026-11-14T10:00:00Z` + "\n",
			[]Entry{{Pin: p, State: StateUnconfirmed, Comment: `label="laptop" from=192.0.2.7:51000 at=2026-11-14T10:00:00Z`}}, nil},
		{"comment without state is confirmed", p + " # hand added\n",
			[]Entry{{Pin: p, State: StateConfirmed, Comment: "hand added"}}, nil},
		{"tab separates fields", p + "\tstate=unconfirmed\n", []Entry{{Pin: p, State: StateUnconfirmed}}, nil},
		{"blank, whitespace-only and comment lines", "\n   \n\t\n# a comment\n   # indented comment\n", nil, nil},
		{"unknown tag ignored with note", p + " label=x\n",
			[]Entry{{Pin: p, State: StateConfirmed}}, []Note{{Line: 1, Token: "label=x"}}},
		{"unknown tags beside state each noted", "# header\n" + p + " via=qr state=unconfirmed future\n",
			[]Entry{{Pin: p, State: StateUnconfirmed}}, []Note{{Line: 2, Token: "via=qr"}, {Line: 2, Token: "future"}}},
		{"entries kept in file order", q + "\n" + p + " state=unconfirmed\n",
			[]Entry{{Pin: q, State: StateConfirmed}, {Pin: p, State: StateUnconfirmed}}, nil},
		{"duplicate pin deduped, first line wins", p + " state=unconfirmed # first\n" + p + " # second\n",
			[]Entry{{Pin: p, State: StateUnconfirmed, Comment: "first"}}, nil},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			res, err := loadString(t, tc.content)
			if err != nil {
				t.Fatalf("LoadAuthorized: %v", err)
			}
			if len(res.Entries) != len(tc.entries) || (len(tc.entries) > 0 && !reflect.DeepEqual(res.Entries, tc.entries)) {
				t.Errorf("Entries = %+v, want %+v", res.Entries, tc.entries)
			}
			if len(res.Notes) != len(tc.notes) || (len(tc.notes) > 0 && !reflect.DeepEqual(res.Notes, tc.notes)) {
				t.Errorf("Notes = %+v, want %+v", res.Notes, tc.notes)
			}
		})
	}

	malformed := []struct {
		name    string
		content string
		line    int
	}{
		{"duplicate state tokens", p + " state=confirmed state=unconfirmed\n", 1},
		{"duplicate identical state tokens", p + " state=confirmed state=confirmed\n", 1},
		{"CRLF entry line", p + "\r\n", 1},
		{"CRLF comment line", q + "\n# note\r\n", 2},
		{"pin field with vertical tab", p + "\v state=confirmed\n", 1},
		{"pin field with form feed", p + "\f\n", 1},
		{"pin field with no-break space", p + "\u00a0\n", 1},
		{"pin glued to comment", p + "#c\n", 1},
		{"non-canonical base64 spelling", nonCanonicalVariant(t, p) + "\n", 1},
		{"short pin", p[:20] + "\n", 1},
		{"token before pin", "state=confirmed " + p + "\n", 1},
		{"line number counts every line", "# c\n\n" + q + "\nnot-a-pin\n", 4},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			res, err := loadString(t, tc.content)
			assertMalformed(t, res, err, "", tc.line)
		})
	}
}

func TestLoadAuthorized_MissingFileIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", "authorized_clients")
	res, err := LoadAuthorized(path)
	if err != nil {
		t.Fatalf("LoadAuthorized(missing) err = %v, want nil", err)
	}
	if len(res.Entries) != 0 || len(res.Notes) != 0 {
		t.Errorf("LoadAuthorized(missing) = %+v, want empty", res)
	}
	assertAbsent(t, path)
	assertAbsent(t, filepath.Dir(path))
}

func TestLoadAuthorized_RoundTripPreservesStateAndComments(t *testing.T) {
	a, b, c, n := testPin("rt-a"), testPin("rt-b"), testPin("rt-c"), testPin("rt-new")
	original := "# trusted clients\n" +
		"\n" +
		a + "\n" +
		b + "\tstate=unconfirmed  label=x # phone  (old)\n" +
		"   # indented comment\t\n" +
		c + " state=unconfirmed # laptop\n"
	path := filepath.Join(t.TempDir(), "authorized_clients")
	writeRaw(t, path, original)

	res, err := LoadAuthorized(path)
	if err != nil {
		t.Fatalf("LoadAuthorized: %v", err)
	}
	wantEntries := []Entry{
		{Pin: a, State: StateConfirmed},
		{Pin: b, State: StateUnconfirmed, Comment: "phone  (old)"},
		{Pin: c, State: StateUnconfirmed, Comment: "laptop"},
	}
	if !reflect.DeepEqual(res.Entries, wantEntries) {
		t.Errorf("Entries = %+v, want %+v", res.Entries, wantEntries)
	}

	added, err := AppendAuthorized(path, Entry{Pin: n, State: StateUnconfirmed, Comment: `label="tablet"`})
	if err != nil || !added {
		t.Fatalf("AppendAuthorized = (%v, %v), want (true, nil)", added, err)
	}
	afterAppend := original + n + ` state=unconfirmed # label="tablet"` + "\n"
	if got := readRaw(t, path); got != afterAppend {
		t.Fatalf("after append file =\n%q\nwant\n%q", got, afterAppend)
	}

	if err := PromoteAuthorized(path, c); err != nil {
		t.Fatalf("PromoteAuthorized: %v", err)
	}
	afterPromote := strings.Replace(afterAppend, c+" state=unconfirmed # laptop\n", c+" state=confirmed # laptop\n", 1)
	if got := readRaw(t, path); got != afterPromote {
		t.Fatalf("after promote file =\n%q\nwant\n%q", got, afterPromote)
	}

	added, err = AppendAuthorized(path, Entry{Pin: testPin("rt-plain"), State: StateConfirmed})
	if err != nil || !added {
		t.Fatalf("AppendAuthorized(no comment) = (%v, %v), want (true, nil)", added, err)
	}
	afterPlain := afterPromote + testPin("rt-plain") + " state=confirmed\n"
	if got := readRaw(t, path); got != afterPlain {
		t.Fatalf("after comment-less append file =\n%q\nwant\n%q", got, afterPlain)
	}

	res, err = LoadAuthorized(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	wantEntries = []Entry{
		{Pin: a, State: StateConfirmed},
		{Pin: b, State: StateUnconfirmed, Comment: "phone  (old)"},
		{Pin: c, State: StateConfirmed, Comment: "laptop"},
		{Pin: n, State: StateUnconfirmed, Comment: `label="tablet"`},
		{Pin: testPin("rt-plain"), State: StateConfirmed},
	}
	if !reflect.DeepEqual(res.Entries, wantEntries) {
		t.Errorf("reloaded Entries = %+v, want %+v", res.Entries, wantEntries)
	}
}

func TestLoadAuthorized_BadPinRejectsWholeFile(t *testing.T) {
	good1, good2 := testPin("bad-1"), testPin("bad-2")
	path := filepath.Join(t.TempDir(), "authorized_clients")
	content := good1 + " state=unconfirmed\n" + good2[:43] + "\n" + good2 + "\n"
	writeRaw(t, path, content)

	res, err := LoadAuthorized(path)
	assertMalformed(t, res, err, path, 2)
	// Nothing from a rejected file is trusted, not even the good line before the bad one.
	if _, ok := Allowed(res)[good1]; ok {
		t.Errorf("Allowed(rejected result) contains the line before the bad pin")
	}
	if got := readRaw(t, path); got != content {
		t.Errorf("loading changed the file")
	}
}

func TestLoadAuthorized_UnknownStateToken(t *testing.T) {
	p, q := testPin("unknown-state-p"), testPin("unknown-state-q")
	res, err := loadString(t, q+"\n"+p+" state=revoked # from a newer version\n")
	if err != nil {
		t.Fatalf("unknown state value must not reject the file: %v", err)
	}
	want := []Entry{
		{Pin: q, State: StateConfirmed},
		{Pin: p, State: StateUnknown, Comment: "from a newer version"},
	}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Errorf("Entries = %+v, want %+v", res.Entries, want)
	}
	if wantNotes := []Note{{Line: 2, Token: "state=revoked"}}; !reflect.DeepEqual(res.Notes, wantNotes) {
		t.Errorf("Notes = %+v, want %+v", res.Notes, wantNotes)
	}
	for s, want := range map[State]string{StateConfirmed: "confirmed", StateUnconfirmed: "unconfirmed", StateUnknown: "unknown"} {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}

func TestAllowed_IncludesEveryState(t *testing.T) {
	c, u, k := testPin("allowed-c"), testPin("allowed-u"), testPin("allowed-k")
	want := map[string]struct{}{c: {}, u: {}, k: {}}

	t.Run("from entries", func(t *testing.T) {
		got := Allowed(LoadResult{Entries: []Entry{
			{Pin: c, State: StateConfirmed},
			{Pin: u, State: StateUnconfirmed},
			{Pin: k, State: StateUnknown},
		}})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Allowed = %v, want %v", got, want)
		}
	})
	t.Run("from a loaded file", func(t *testing.T) {
		res, err := loadString(t, c+"\n"+u+" state=unconfirmed\n"+k+" state=suspended label=x\n")
		if err != nil {
			t.Fatalf("LoadAuthorized: %v", err)
		}
		if got := Allowed(res); !reflect.DeepEqual(got, want) {
			t.Errorf("Allowed = %v, want %v", got, want)
		}
	})
	t.Run("empty result is an empty non-nil set", func(t *testing.T) {
		got := Allowed(LoadResult{})
		if got == nil || len(got) != 0 {
			t.Errorf("Allowed(empty) = %#v, want empty non-nil map", got)
		}
	})
	t.Run("package doc states the access invariant", func(t *testing.T) {
		files, err := filepath.Glob("*.go")
		if err != nil {
			t.Fatal(err)
		}
		var doc strings.Builder
		fset := token.NewFileSet()
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			af, err := parser.ParseFile(fset, f, nil, parser.ParseComments|parser.PackageClauseOnly)
			if err != nil {
				t.Fatal(err)
			}
			if af.Doc != nil {
				doc.WriteString(af.Doc.Text())
			}
		}
		text := strings.ToLower(regexp.MustCompile(`\s+`).ReplaceAllString(doc.String(), " "))
		for _, phrase := range []string{"no tag may restrict access", "revocation is deleting the line"} {
			if !strings.Contains(text, phrase) {
				t.Errorf("package doc does not state %q; doc is %q", phrase, text)
			}
		}
	})
}

func TestLoadAuthorizedAtStart_MalformedIsDistinctColdStartError(t *testing.T) {
	dir := t.TempDir()
	p := testPin("start-p")

	bad := filepath.Join(dir, "bad")
	writeRaw(t, bad, p+"\nbroken\n")
	res, err := LoadAuthorizedAtStart(bad)
	if !errors.Is(err, ErrColdStart) {
		t.Errorf("errors.Is(err, ErrColdStart) = false for %v", err)
	}
	assertMalformed(t, res, err, bad, 2)

	// The runtime loader reports the same file as malformed but not as a cold start.
	if _, err := LoadAuthorized(bad); !errors.Is(err, ErrMalformed) || errors.Is(err, ErrColdStart) {
		t.Errorf("LoadAuthorized(bad) = %v, want ErrMalformed without ErrColdStart", err)
	}

	good := filepath.Join(dir, "good")
	writeRaw(t, good, p+" state=unconfirmed\n")
	res, err = LoadAuthorizedAtStart(good)
	if err != nil {
		t.Fatalf("LoadAuthorizedAtStart(good) = %v", err)
	}
	if want := []Entry{{Pin: p, State: StateUnconfirmed}}; !reflect.DeepEqual(res.Entries, want) {
		t.Errorf("Entries = %+v, want %+v", res.Entries, want)
	}

	res, err = LoadAuthorizedAtStart(filepath.Join(dir, "missing"))
	if err != nil || len(res.Entries) != 0 {
		t.Errorf("LoadAuthorizedAtStart(missing) = (%+v, %v), want (empty, nil)", res, err)
	}
}

func TestAppendAuthorized_IdempotentAndNeverDowngrades(t *testing.T) {
	p := testPin("idem-p")

	t.Run("second append is a no-op", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authorized_clients")
		added, err := AppendAuthorized(path, Entry{Pin: p, State: StateUnconfirmed, Comment: "one"})
		if err != nil || !added {
			t.Fatalf("first append = (%v, %v), want (true, nil)", added, err)
		}
		before := readRaw(t, path)
		if want := p + " state=unconfirmed # one\n"; before != want {
			t.Fatalf("file = %q, want %q", before, want)
		}
		added, err = AppendAuthorized(path, Entry{Pin: p, State: StateUnconfirmed, Comment: "two"})
		if err != nil || added {
			t.Fatalf("second append = (%v, %v), want (false, nil)", added, err)
		}
		if got := readRaw(t, path); got != before {
			t.Errorf("second append changed the file: %q", got)
		}
	})
	for name, line := range map[string]string{
		"explicit confirmed": p + " state=confirmed # desk\n",
		"hand-added bare":    p + "\n",
	} {
		t.Run("confirmed stays confirmed: "+name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authorized_clients")
			writeRaw(t, path, "# keep\n"+line)
			added, err := AppendAuthorized(path, Entry{Pin: p, State: StateUnconfirmed})
			if err != nil || added {
				t.Fatalf("append over confirmed = (%v, %v), want (false, nil)", added, err)
			}
			if got := readRaw(t, path); got != "# keep\n"+line {
				t.Errorf("file changed to %q", got)
			}
			res, err := LoadAuthorized(path)
			if err != nil || len(res.Entries) != 1 || res.Entries[0].State != StateConfirmed {
				t.Errorf("after append: (%+v, %v), want one confirmed entry", res, err)
			}
		})
	}
}

func TestAppendAuthorized_RejectsInvalidInput(t *testing.T) {
	p := testPin("invalid-p")
	cases := map[string]Entry{
		"empty pin":                {Pin: "", State: StateUnconfirmed},
		"pin with trailing space":  {Pin: p + " ", State: StateUnconfirmed},
		"pin with trailing LF":     {Pin: p + "\n", State: StateUnconfirmed},
		"pin with leading tab":     {Pin: "\t" + p, State: StateUnconfirmed},
		"non-canonical pin":        {Pin: nonCanonicalVariant(t, p), State: StateUnconfirmed},
		"short pin":                {Pin: p[:43], State: StateUnconfirmed},
		"unknown state":            {Pin: p, State: StateUnknown},
		"out-of-range state":       {Pin: p, State: State(42)},
		"comment with LF":          {Pin: p, State: StateUnconfirmed, Comment: "a\nb"},
		"comment with CR":          {Pin: p, State: StateUnconfirmed, Comment: "a\rb"},
		"comment with NUL":         {Pin: p, State: StateUnconfirmed, Comment: "a\x00b"},
		"comment with DEL":         {Pin: p, State: StateUnconfirmed, Comment: "a\x7fb"},
		"comment with ESC":         {Pin: p, State: StateUnconfirmed, Comment: "\x1b[31mred"},
		"comment with non-ASCII":   {Pin: p, State: StateUnconfirmed, Comment: "caf\u00e9"},
		"comment with line sep":    {Pin: p, State: StateUnconfirmed, Comment: "a\u2028b"},
		"comment with vertical tb": {Pin: p, State: StateUnconfirmed, Comment: "a\vb"},
	}
	// Positive control: the same files accept a valid entry whose comment uses
	// the edges of the allowed text (tab, space, '#', '~'), so every rejection
	// below is caused by the one invalid field.
	t.Run("control: valid entry is accepted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "new", "authorized_clients")
		added, err := AppendAuthorized(path, Entry{Pin: p, State: StateUnconfirmed, Comment: "a\tb #c ~"})
		if err != nil || !added {
			t.Fatalf("valid append = (%v, %v), want (true, nil)", added, err)
		}
		if want := p + " state=unconfirmed # a\tb #c ~\n"; readRaw(t, path) != want {
			t.Errorf("file = %q, want %q", readRaw(t, path), want)
		}
	})
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			missing := filepath.Join(dir, "new", "authorized_clients")
			added, err := AppendAuthorized(missing, e)
			if err == nil || added {
				t.Errorf("append to new file = (%v, %v), want (false, error)", added, err)
			}
			assertAbsent(t, missing)

			existing := filepath.Join(dir, "authorized_clients")
			const seed = "# existing\n"
			writeRaw(t, existing, seed)
			added, err = AppendAuthorized(existing, e)
			if err == nil || added {
				t.Errorf("append to existing file = (%v, %v), want (false, error)", added, err)
			}
			if got := readRaw(t, existing); got != seed {
				t.Errorf("file changed to %q", got)
			}
		})
	}
}

func TestRemoveAuthorized_PrefixRules(t *testing.T) {
	head := [6]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60}
	twinA, twinB := pinWithHead(head, "twin-a"), pinWithHead(head, "twin-b")
	other := testPin("remove-other")
	if twinA[:8] != twinB[:8] || twinA[:9] == twinB[:9] {
		t.Fatalf("fixture: twins must share exactly an 8-char prefix: %q %q", twinA, twinB)
	}
	content := "# clients\n" +
		twinA + " state=unconfirmed # first twin\n" +
		"\n" +
		twinB + "\n" +
		other + " state=confirmed # other\n"

	setup := func(t *testing.T) string {
		path := filepath.Join(t.TempDir(), "authorized_clients")
		writeRaw(t, path, content)
		return path
	}

	t.Run("prefix shorter than 8", func(t *testing.T) {
		path := setup(t)
		_, err := RemoveAuthorized(path, other[:7])
		if !errors.Is(err, ErrPrefixShort) {
			t.Errorf("err = %v, want ErrPrefixShort", err)
		}
		if readRaw(t, path) != content {
			t.Errorf("file changed")
		}
	})
	t.Run("ambiguous prefix lists candidates", func(t *testing.T) {
		path := setup(t)
		_, err := RemoveAuthorized(path, twinA[:8])
		var ae *AmbiguousPrefixError
		if !errors.As(err, &ae) {
			t.Fatalf("err = %v, want *AmbiguousPrefixError", err)
		}
		if ae.Prefix != twinA[:8] {
			t.Errorf("Prefix = %q, want %q", ae.Prefix, twinA[:8])
		}
		if len(ae.Candidates) != 2 {
			t.Fatalf("Candidates = %q, want 2", ae.Candidates)
		}
		for _, c := range ae.Candidates {
			if len(c) < 8 || !(strings.HasPrefix(twinA, c) || strings.HasPrefix(twinB, c)) {
				t.Errorf("candidate %q is not a prefix of a matching pin", c)
			}
		}
		if readRaw(t, path) != content {
			t.Errorf("file changed")
		}
	})
	t.Run("no match", func(t *testing.T) {
		path := setup(t)
		_, err := RemoveAuthorized(path, testPin("absent")[:12])
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
		if readRaw(t, path) != content {
			t.Errorf("file changed")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authorized_clients")
		if _, err := RemoveAuthorized(path, other); !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
		assertAbsent(t, path)
	})
	t.Run("longer unique prefix removes that line only", func(t *testing.T) {
		path := setup(t)
		removed, err := RemoveAuthorized(path, twinA[:9])
		if err != nil {
			t.Fatalf("RemoveAuthorized: %v", err)
		}
		if want := (Entry{Pin: twinA, State: StateUnconfirmed, Comment: "first twin"}); removed != want {
			t.Errorf("removed = %+v, want %+v", removed, want)
		}
		want := "# clients\n" + "\n" + twinB + "\n" + other + " state=confirmed # other\n"
		if got := readRaw(t, path); got != want {
			t.Errorf("file =\n%q\nwant\n%q", got, want)
		}
	})
	t.Run("exact pin", func(t *testing.T) {
		path := setup(t)
		removed, err := RemoveAuthorized(path, other)
		if err != nil {
			t.Fatalf("RemoveAuthorized: %v", err)
		}
		if want := (Entry{Pin: other, State: StateConfirmed, Comment: "other"}); removed != want {
			t.Errorf("removed = %+v, want %+v", removed, want)
		}
		want := "# clients\n" + twinA + " state=unconfirmed # first twin\n" + "\n" + twinB + "\n"
		if got := readRaw(t, path); got != want {
			t.Errorf("file =\n%q\nwant\n%q", got, want)
		}
	})
}

func TestPromoteAuthorized_NeverResurrectsRemovedPin(t *testing.T) {
	p, keep := testPin("promote-p"), testPin("promote-keep")
	path := filepath.Join(t.TempDir(), "authorized_clients")
	writeRaw(t, path, keep+"\n")

	if added, err := AppendAuthorized(path, Entry{Pin: p, State: StateUnconfirmed}); err != nil || !added {
		t.Fatalf("append = (%v, %v)", added, err)
	}
	if _, err := RemoveAuthorized(path, p); err != nil {
		t.Fatalf("remove: %v", err)
	}
	afterRemove := readRaw(t, path)
	if afterRemove != keep+"\n" {
		t.Fatalf("after remove file = %q", afterRemove)
	}

	if err := PromoteAuthorized(path, p); !errors.Is(err, ErrNotFound) {
		t.Errorf("promote of removed pin = %v, want ErrNotFound", err)
	}
	if got := readRaw(t, path); got != afterRemove {
		t.Errorf("promote changed the file to %q", got)
	}
	if res, err := LoadAuthorized(path); err != nil || len(Allowed(res)) != 1 {
		t.Errorf("after promote: Allowed(%+v) err %v, want only the kept pin", res, err)
	} else if _, ok := Allowed(res)[p]; ok {
		t.Errorf("removed pin resurrected by promote")
	}

	t.Run("already confirmed is a no-op", func(t *testing.T) {
		if err := PromoteAuthorized(path, keep); err != nil {
			t.Errorf("promote confirmed = %v, want nil", err)
		}
		if got := readRaw(t, path); got != afterRemove {
			t.Errorf("file changed to %q", got)
		}
	})
	t.Run("missing file is not created", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "authorized_clients")
		if err := PromoteAuthorized(missing, p); !errors.Is(err, ErrNotFound) {
			t.Errorf("promote on missing file = %v, want ErrNotFound", err)
		}
		assertAbsent(t, missing)
	})
}

func TestAuthorizedWriters_RefuseMalformedFile(t *testing.T) {
	p, n := testPin("refuse-p"), testPin("refuse-new")
	content := p + " state=unconfirmed\n" + "not a pin\n"
	writers := map[string]func(path string) error{
		"append": func(path string) error {
			_, err := AppendAuthorized(path, Entry{Pin: n, State: StateUnconfirmed})
			return err
		},
		"remove": func(path string) error {
			_, err := RemoveAuthorized(path, p)
			return err
		},
		"promote": func(path string) error { return PromoteAuthorized(path, p) },
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authorized_clients")
			writeRaw(t, path, content)
			err := write(path)
			var me *MalformedError
			if !errors.As(err, &me) || !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want *MalformedError matching ErrMalformed", err)
			}
			if me.Line != 2 {
				t.Errorf("Line = %d, want 2", me.Line)
			}
			if got := readRaw(t, path); got != content {
				t.Errorf("writer rewrote a malformed file: %q", got)
			}
		})
	}
}

func TestAuthorizedWriters_FileLockAndDirModes(t *testing.T) {
	p, q := testPin("modes-p"), testPin("modes-q")
	dir := filepath.Join(t.TempDir(), "state", "quic-link")
	path := filepath.Join(dir, "authorized_clients")
	lock := path + ".lock"

	if added, err := AppendAuthorized(path, Entry{Pin: p, State: StateUnconfirmed}); err != nil || !added {
		t.Fatalf("append to missing dir = (%v, %v)", added, err)
	}
	assertMode(t, dir, 0o700)
	assertMode(t, path, 0o600)
	assertMode(t, lock, 0o600)

	// A file loosened by hand is written back private.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if added, err := AppendAuthorized(path, Entry{Pin: q, State: StateConfirmed}); err != nil || !added {
		t.Fatalf("second append = (%v, %v)", added, err)
	}
	assertMode(t, path, 0o600)

	if err := PromoteAuthorized(path, p); err != nil {
		t.Fatalf("promote: %v", err)
	}
	assertMode(t, path, 0o600)
	if _, err := RemoveAuthorized(path, q); err != nil {
		t.Fatalf("remove: %v", err)
	}
	assertMode(t, path, 0o600)
	// The lock file is never deleted.
	assertMode(t, lock, 0o600)
	if want := p + " state=confirmed\n"; readRaw(t, path) != want {
		t.Errorf("file = %q, want %q", readRaw(t, path), want)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"authorized_clients", "authorized_clients.lock"}; !reflect.DeepEqual(names, want) {
		t.Errorf("dir holds %q, want %q (no temp files left)", names, want)
	}
}
