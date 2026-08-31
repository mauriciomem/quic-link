package main

// The read half of publishing a name. Until this existed, a name published on a
// running agent was disclosed by nothing: it could be added over the control
// plane and reported by no command, so the agent's own log was the only record
// and it went away when the process did. Three names once served traffic on a
// two-machine rig while the only listing surface showed none of them.

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

// sanitizedVhost is one published name with every agent-supplied field already
// run through the same sanitiser the route listing uses. Like that type, it can
// only be built from sanitised data, by construction.
type sanitizedVhost struct {
	Host    string `json:"host"`
	Address string `json:"address"`
	Builtin bool   `json:"builtin"`
	// Provenance is reported, and never used to decide how anything is
	// rendered. The agent chooses this string; a renderer that branched on it
	// would let the far end pick which words a person sees.
	Provenance string `json:"provenance"`
}

// vhostsJSONOutput is the --json shape. It mirrors the daemon's snapshot field
// for field, carrying only sanitised entries.
type vhostsJSONOutput struct {
	Schema int              `json:"schema"`
	Server string           `json:"server"`
	Vhosts []sanitizedVhost `json:"vhosts"`
}

func sanitizeVhosts(in []daemon.VhostInfo) []sanitizedVhost {
	out := make([]sanitizedVhost, len(in))
	for i, v := range in {
		out[i] = sanitizedVhost{
			Host:       sanitizeAgentString(v.Host),
			Address:    sanitizeAgentString(v.Address),
			Builtin:    v.Builtin,
			Provenance: sanitizeAgentString(v.Provenance),
		}
	}
	return out
}

// originLabel says where a name came from, in words chosen here.
//
// The agent's own word is reported in the machine-readable output but never
// printed as prose: mapping it to a fixed set locally means a compromised agent
// cannot choose the sentence a person reads, only which of these it selects. An
// unrecognised value says so rather than being passed through, because the set
// is open and a new one is not an error.
func originLabel(provenance string) string {
	switch provenance {
	case "runtime":
		return "published while running"
	case "config":
		return "from configuration"
	case "builtin":
		return "builtin"
	default:
		return "origin not recognised"
	}
}

// printVhostsHuman writes the free-form rendering. Every field has already been
// sanitised, so no call site here needs escaping of its own.
func printVhostsHuman(w io.Writer, server string, vhosts []sanitizedVhost) {
	if len(vhosts) == 0 {
		fmt.Fprintf(w, "server %q publishes no names\n", server)
		return
	}
	fmt.Fprintf(w, "names published by %q:\n", server)
	for _, v := range vhosts {
		fmt.Fprintf(w, "  %-34s %-30s (%s)\n", v.Host, v.Address, originLabel(v.Provenance))
	}
}

func newVhostsCmd(a *app) *cobra.Command {
	var jsonFlag bool
	cmd := &cobra.Command{
		Use:   "vhosts [SERVER]",
		Short: "List the names a server publishes",
		Long: `List the hostnames one server currently answers for.

The list is fetched from that server's agent when the command runs, so it
reflects what the agent is serving now rather than what a configuration file
says. It includes names the agent's operator configured and names published
while it was running; where each came from is reported, because only the second
kind could later be taken back.

SERVER may be omitted when exactly one server is known.

--json prints the frozen machine-readable shape to stdout (CONTRACT):
  {"schema":1,"server":"...","vhosts":[{"host":"...","address":"...",
   "builtin":false,"provenance":"config|runtime|builtin"}]}

Reading this asks nothing of the agent's operator: reporting what a name table
holds is not the same as changing it, so no permission is needed for it.`,
		Args: wrapArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVhosts(cmd, a, args, jsonFlag)
		},
	}
	cmd.Flags().BoolVar(&jsonFlag, "json", false, "print the machine-readable shape")
	cmd.AddCommand(newVhostsRmCmd(a))
	return cmd
}

func newVhostsRmCmd(a *app) *cobra.Command {
	var jsonFlag bool
	cmd := &cobra.Command{
		Use:   "rm NAME [SERVER]",
		Short: "Take back a name that was published while a server was running",
		Long: `Withdraw a hostname that was published on a running agent.

Only a name published this way can be withdrawn. A name from the agent's own
configuration belongs to whoever runs that agent, and no setting makes it
removable from here — the refusal says which kind is in the way.

Withdrawing changes what the agent serves, so like publishing it is refused
unless that agent's operator allowed remote changes.

If a pattern in the agent's configuration covers the name, the name still
resolves after the exact entry is gone, at whatever address that pattern points
to. When that happens both the pattern and that address are reported, because a
withdrawal that leaves a name answered is not what "withdrawn" sounds like, and
knowing it still answers is only half of what a reader needs.

SERVER may be omitted when exactly one server is known.

--json prints the frozen machine-readable shape to stdout (CONTRACT):
  {"schema":1,"server":"...","host":"...","shadowed_by":"*...",
   "shadowed_by_address":"tcp://127.0.0.1:3000"}
Both shadow fields are absent unless a pattern took over, and absent together.`,
		Args: wrapArgs(cobra.RangeArgs(1, 2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVhostsRm(cmd, a, args, jsonFlag)
		},
	}
	cmd.Flags().BoolVar(&jsonFlag, "json", false, "print the machine-readable shape")
	return cmd
}

// runVhostsRm relays a withdrawal through the daemon. Every way it can fail has
// already been given its message and status by the daemon's provider; both are
// relayed rather than re-worded here.
func runVhostsRm(cmd *cobra.Command, a *app, args []string, jsonFlag bool) error {
	host := args[0]
	if host == "" {
		return usageErrorf("a name to withdraw is required")
	}

	serverName, err := autoSelectServer(a, args[1:])
	if err != nil {
		return err
	}
	if err := requireKnownServer(a, serverName); err != nil {
		return err
	}

	sock, err := daemonSocketPath(a.cfg)
	if err != nil {
		return fmt.Errorf("resolve socket path: %w", err)
	}

	raw, err := ipc.NewClient(sock).WithdrawJSON(serverName, host)
	if err != nil {
		return relayIPCError(cmd, "withdraw", err, relayCanReturnRoutesError)
	}

	var snap daemon.WithdrawSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("parse withdraw response: %w", err)
	}

	if jsonFlag {
		out := withdrawJSONOutput{
			Schema:            snap.Schema,
			Server:            snap.Server,
			Host:              sanitizeAgentString(snap.Host),
			ShadowedBy:        sanitizeAgentString(snap.ShadowedBy),
			ShadowedByAddress: sanitizeAgentString(snap.ShadowedByAddress),
		}
		b, merr := json.Marshal(out)
		if merr != nil {
			return fmt.Errorf("marshal withdraw output: %w", merr)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", b)
		return nil
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "withdrawn: %s\n", sanitizeAgentString(snap.Host))
	if snap.ShadowedBy != "" {
		// The name is gone and still answers. Saying only "withdrawn" here would
		// be true and would still mislead — and naming the pattern without where
		// it points would raise the reader's next question without answering it,
		// since the address is usually a different service than the one just
		// withdrawn.
		fmt.Fprintf(w, "  still answered by %s in that agent's configuration, which points at %s\n",
			sanitizeAgentString(snap.ShadowedBy), sanitizeAgentString(snap.ShadowedByAddress))
	}
	return nil
}

// withdrawJSONOutput is the --json shape, carrying only sanitised fields.
//
// The two shadow fields are absent together: a pattern with no address, or an
// address with no pattern, is not a document this produces, so a reader has one
// condition to test rather than two that could disagree.
type withdrawJSONOutput struct {
	Schema            int    `json:"schema"`
	Server            string `json:"server"`
	Host              string `json:"host"`
	ShadowedBy        string `json:"shadowed_by,omitempty"`
	ShadowedByAddress string `json:"shadowed_by_address,omitempty"`
}

// runVhosts relays a listing request through the daemon and prints the result.
// Every way the relay can fail short of success has already been given its own
// message and status by the daemon's provider; both are relayed verbatim rather
// than re-worded here.
func runVhosts(cmd *cobra.Command, a *app, args []string, jsonFlag bool) error {
	serverName, err := autoSelectServer(a, args)
	if err != nil {
		return err
	}
	if err := requireKnownServer(a, serverName); err != nil {
		return err
	}

	sock, err := daemonSocketPath(a.cfg)
	if err != nil {
		return fmt.Errorf("resolve socket path: %w", err)
	}

	raw, err := ipc.NewClient(sock).VhostsJSON(serverName)
	if err != nil {
		return relayIPCError(cmd, "vhosts", err, relayCanReturnRoutesError)
	}

	var snap daemon.VhostsSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("parse published-name response: %w", err)
	}

	vhosts := sanitizeVhosts(snap.Vhosts)

	if jsonFlag {
		out := vhostsJSONOutput{Schema: snap.Schema, Server: snap.Server, Vhosts: vhosts}
		b, merr := json.Marshal(out)
		if merr != nil {
			return fmt.Errorf("marshal published-name output: %w", merr)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", b)
		return nil
	}

	printVhostsHuman(cmd.OutOrStdout(), snap.Server, vhosts)
	return nil
}
