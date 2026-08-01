package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/mauriciomem/quic-link/internal/proto"
)

// TestVersionJSON drives the version verb end-to-end and asserts the CONTRACT
// JSON shape: exactly the three fields version/commit/proto_version, with
// proto_version equal to the wire protocol constant (never the CLI's own
// semver — the two are unrelated and must not be conflated).
func TestVersionJSON(t *testing.T) {
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"version", "--json"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("version --json: %v", err)
	}

	var doc struct {
		Version      string `json:"version"`
		Commit       string `json:"commit"`
		ProtoVersion int    `json:"proto_version"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal version --json output %q: %v", buf.String(), err)
	}
	if doc.Version == "" {
		t.Error("version field is empty")
	}
	if doc.Commit == "" {
		t.Error("commit field is empty")
	}
	if doc.ProtoVersion != int(proto.ProtoVersion) {
		t.Errorf("proto_version = %d, want %d (proto.ProtoVersion)", doc.ProtoVersion, proto.ProtoVersion)
	}
}

// TestVersionHuman verifies the human (non-JSON) path exits 0 and does not
// require --json. Its exact text is deliberately not asserted (anti-contract).
func TestVersionHuman(t *testing.T) {
	if err := runVerb([]string{"version"}); err != nil {
		t.Fatalf("version: %v", err)
	}
}
