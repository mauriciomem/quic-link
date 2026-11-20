/**
 * @spec-handoff
 * @interface TestMain(m *testing.M)  // goleak.VerifyTestMain
 * @behavior
 *   - The package leaks no goroutine: every lock wait, child process and pipe copier is finished when a test returns
 *   - Shared test helpers live here: deterministic canonical pins, raw file helpers, mode checks
 * @see ./authorized_test.go
 */

package pairstate

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// testPin returns a canonical pin derived from seed.
func testPin(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// pinWithHead returns a canonical pin whose digest starts with head (6 bytes
// give an identical 8-character prefix); the rest is derived from seed.
func pinWithHead(head [6]byte, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	copy(sum[:6], head[:])
	return base64.StdEncoding.EncodeToString(sum[:])
}

// nonCanonicalVariant returns a spelling of pin that decodes to the same
// digest but sets a padding bit, so only a strict parser refuses it.
func nonCanonicalVariant(t *testing.T, pin string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if len(pin) != 44 || pin[43] != '=' {
		t.Fatalf("unexpected pin shape %q", pin)
	}
	i := strings.IndexByte(alphabet, pin[42])
	v := pin[:42] + string(alphabet[i|1]) + "="
	if v == pin {
		t.Fatalf("variant equals pin")
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != pin {
		t.Fatalf("variant %q does not decode to the same digest (err %v)", v, err)
	}
	return v
}

func writeRaw(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readRaw(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Errorf("stat %s: %v", path, err)
		return
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("mode of %s = %#o, want %#o", path, got, want)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("%s should not exist (stat err %v)", path, err)
	}
}
