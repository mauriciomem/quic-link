package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/buildinfo"
	"github.com/mauriciomem/quic-link/internal/proto"
)

// versionDoc is the --json CONTRACT shape: exactly these three fields.
// version and commit answer "what tool build is this"; proto_version answers
// "what wire protocol does it speak" (the frame-layout constant the agent and
// client must agree on). The two are unrelated and must never be conflated.
type versionDoc struct {
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	ProtoVersion int    `json:"proto_version"`
}

func newVersionCmd() *cobra.Command {
	var jsonFlag bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the CLI build version and the wire protocol version",
		Long: `Print build metadata: the CLI's own semver (injected at build time via
-ldflags -X), the git commit it was built from, and the wire protocol
version (proto.ProtoVersion) — unrelated numbers answering two different
questions. Human output is free-form (anti-contract); --json is CONTRACT.`,
		Args: wrapArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc := versionDoc{
				Version:      buildinfo.Version(),
				Commit:       buildinfo.Commit(),
				ProtoVersion: int(proto.ProtoVersion),
			}
			if jsonFlag {
				b, err := json.Marshal(doc)
				if err != nil {
					return fmt.Errorf("marshal version doc: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n", b)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "quic-link %s (commit %s, wire protocol v%d)\n",
				doc.Version, doc.Commit, doc.ProtoVersion)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonFlag, "json", false, "print machine-readable JSON (CONTRACT)")
	return cmd
}
