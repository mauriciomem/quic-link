/**
 * @spec-handoff
 * @interface AppendAuthorized / RemoveAuthorized exercised from two re-executed copies of this test binary
 * @behavior
 *   - Two processes appending concurrently both survive: the exact union of their pins is on disk
 *   - A pin removed while another process appends stays removed (no read-modify-write resurrects it)
 *   - Control: an unlocked read-pause-write writer forced into read,read,write,write loses a pin, proving the observer can see a lost update
 * @edge-cases
 *   - TestAuthorizedHelperProcess is the re-exec entry point; it returns at once unless PAIRSTATE_HELPER=1
 *   - This is the only file in the package that starts a process: it re-executes its own test binary and nothing else
 * @see ./authorized.go
 */

package pairstate

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/atomicfile"
)

const (
	envHelper = "PAIRSTATE_HELPER"
	envRole   = "PAIRSTATE_ROLE"
	envPath   = "PAIRSTATE_PATH"
	envPins   = "PAIRSTATE_PINS"
	envSync   = "PAIRSTATE_SYNC"
	envName   = "PAIRSTATE_NAME"

	roleAppend         = "append"          // AppendAuthorized every pin
	roleRemoveChurn    = "remove-churn"    // remove the first pin, then append+remove each other pin
	roleUnlockedAppend = "unlocked-append" // control: read, pause, write without any lock
)

// pinSetOnDisk is an implementation-independent observer: the first field of
// every non-blank, non-comment line.
func pinSetOnDisk(t *testing.T, path string) []string {
	t.Helper()
	var pins []string
	for _, line := range strings.Split(readRaw(t, path), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		pins = append(pins, f[0])
	}
	sort.Strings(pins)
	return pins
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func pinList(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = testPin(fmt.Sprintf("%s-%d", prefix, i))
	}
	return out
}

// waitFile polls for a barrier file.
func waitFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", path)
		}
		time.Sleep(time.Millisecond)
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

type child struct {
	name    string
	out     *bytes.Buffer
	exited  chan struct{}
	exitErr error
}

// startChild re-executes this test binary into TestAuthorizedHelperProcess
// with a minimal environment. The child is always reaped before the test ends.
func startChild(t *testing.T, ctx context.Context, name, role, path, syncDir string, pins []string) *child {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestAuthorizedHelperProcess$", "-test.count=1")
	cmd.Env = []string{
		envHelper + "=1",
		envRole + "=" + role,
		envPath + "=" + path,
		envPins + "=" + strings.Join(pins, ","),
		envSync + "=" + syncDir,
		envName + "=" + name,
	}
	if v, ok := os.LookupEnv("GOCOVERDIR"); ok {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+v)
	}
	out := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &child{name: name, out: out, exited: make(chan struct{})}
	go func() {
		c.exitErr = cmd.Wait()
		close(c.exited)
	}()
	t.Cleanup(func() { <-c.exited })
	return c
}

// wait reaps the child and reports a non-zero exit with its output.
func (c *child) wait() error {
	<-c.exited
	if c.exitErr != nil {
		return fmt.Errorf("child %s: %v\n%s", c.name, c.exitErr, c.out.String())
	}
	return nil
}

// waitBarrier waits for a barrier file a child creates, failing fast if any
// child has already exited without creating it.
func waitBarrier(path string, children ...*child) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		for _, c := range children {
			select {
			case <-c.exited:
				if _, err := os.Stat(path); err == nil {
					return nil
				}
				return fmt.Errorf("child %s exited before %s: %v", c.name, filepath.Base(path), c.wait())
			default:
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", path)
		}
		time.Sleep(time.Millisecond)
	}
}

type childSpec struct {
	role string
	pins []string
}

// runConcurrent starts two children and releases them together once both are
// ready, so their writer calls overlap.
func runConcurrent(t *testing.T, path string, a, b childSpec) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	syncDir := t.TempDir()
	ca := startChild(t, ctx, "a", a.role, path, syncDir, a.pins)
	cb := startChild(t, ctx, "b", b.role, path, syncDir, b.pins)
	for _, n := range []string{"a", "b"} {
		if err := waitBarrier(filepath.Join(syncDir, n+".ready"), ca, cb); err != nil {
			t.Error(err)
		}
	}
	touch(t, filepath.Join(syncDir, "go"))
	for _, c := range []*child{ca, cb} {
		if err := c.wait(); err != nil {
			t.Error(err)
		}
	}
}

func TestAuthorizedAppend_TwoProcessesBothSurvive(t *testing.T) {
	t.Run("control: harness observes a lost update from an unlocked writer", func(t *testing.T) {
		// Each child reads the file, signals, and writes only when told to, so
		// the read-read-write-write interleaving is forced, not hoped for.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		path := filepath.Join(t.TempDir(), "authorized_clients")
		base := testPin("control-base")
		writeRaw(t, path, base+"\n")
		pa, pb := testPin("control-a"), testPin("control-b")
		syncDir := t.TempDir()

		ca := startChild(t, ctx, "a", roleUnlockedAppend, path, syncDir, []string{pa})
		cb := startChild(t, ctx, "b", roleUnlockedAppend, path, syncDir, []string{pb})
		for _, n := range []string{"a", "b"} {
			if err := waitBarrier(filepath.Join(syncDir, n+".read"), ca, cb); err != nil {
				t.Fatal(err)
			}
		}
		touch(t, filepath.Join(syncDir, "a.write"))
		if err := ca.wait(); err != nil {
			t.Fatal(err)
		}
		touch(t, filepath.Join(syncDir, "b.write"))
		if err := cb.wait(); err != nil {
			t.Fatal(err)
		}

		got := pinSetOnDisk(t, path)
		if want := sorted([]string{base, pb}); !reflect.DeepEqual(got, want) {
			t.Fatalf("control did not lose a's pin: file pins %q, want exactly %q", got, want)
		}
	})

	t.Run("locked appends", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authorized_clients")
		as, bs := pinList("proc-a", 40), pinList("proc-b", 40)
		runConcurrent(t, path,
			childSpec{roleAppend, as},
			childSpec{roleAppend, bs})

		if want := sorted(append(append([]string{}, as...), bs...)); !reflect.DeepEqual(pinSetOnDisk(t, path), want) {
			t.Errorf("lost update: file pins %q\nwant exactly %q", pinSetOnDisk(t, path), want)
		}
		res, err := LoadAuthorized(path)
		if err != nil || len(res.Entries) != 80 {
			t.Errorf("LoadAuthorized after concurrent appends = %d entries, err %v; want 80, nil", len(res.Entries), err)
		}
	})
}

func TestAuthorizedRemove_RacingAppendStaysRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_clients")
	target := testPin("revoked-target")
	writeRaw(t, path, target+" state=confirmed # revoke me\n")
	as := pinList("race-append", 40)
	churn := append([]string{target}, pinList("race-churn", 20)...)

	runConcurrent(t, path,
		childSpec{roleAppend, as},
		childSpec{roleRemoveChurn, churn})

	got := pinSetOnDisk(t, path)
	for _, p := range churn {
		for _, g := range got {
			if g == p {
				t.Errorf("removed pin %s was resurrected", p)
			}
		}
	}
	if want := sorted(as); !reflect.DeepEqual(got, want) {
		t.Errorf("file pins %q\nwant exactly %q", got, want)
	}
}

// TestAuthorizedHelperProcess is the child side of the two-process tests. It
// does nothing unless PAIRSTATE_HELPER=1.
func TestAuthorizedHelperProcess(t *testing.T) {
	if os.Getenv(envHelper) != "1" {
		return
	}
	path, syncDir, name := os.Getenv(envPath), os.Getenv(envSync), os.Getenv(envName)
	pins := strings.Split(os.Getenv(envPins), ",")

	switch role := os.Getenv(envRole); role {
	case roleUnlockedAppend:
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		touch(t, filepath.Join(syncDir, name+".read"))
		if err := waitFile(filepath.Join(syncDir, name+".write"), 30*time.Second); err != nil {
			t.Fatal(err)
		}
		out := append(data, []byte(pins[0]+" state=unconfirmed\n")...)
		if err := atomicfile.Write(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
	case roleAppend, roleRemoveChurn:
		touch(t, filepath.Join(syncDir, name+".ready"))
		if err := waitFile(filepath.Join(syncDir, "go"), 30*time.Second); err != nil {
			t.Fatal(err)
		}
		if role == roleAppend {
			for _, p := range pins {
				if added, err := AppendAuthorized(path, Entry{Pin: p, State: StateUnconfirmed}); err != nil || !added {
					t.Fatalf("AppendAuthorized(%s) = (%v, %v), want (true, nil)", p, added, err)
				}
			}
			return
		}
		if e, err := RemoveAuthorized(path, pins[0]); err != nil || e.Pin != pins[0] {
			t.Fatalf("RemoveAuthorized(target) = (%+v, %v)", e, err)
		}
		for _, p := range pins[1:] {
			if added, err := AppendAuthorized(path, Entry{Pin: p, State: StateUnconfirmed}); err != nil || !added {
				t.Fatalf("AppendAuthorized(%s) = (%v, %v), want (true, nil)", p, added, err)
			}
			if e, err := RemoveAuthorized(path, p); err != nil || e.Pin != p {
				t.Fatalf("RemoveAuthorized(%s) = (%+v, %v)", p, e, err)
			}
		}
	default:
		t.Fatalf("unknown helper role %q", role)
	}
}
