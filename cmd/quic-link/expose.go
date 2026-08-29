package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/router"
)

// newExposeCmd builds the "expose" verb: ask a server's agent to publish one of
// its local ports under a hostname, so a browser here can reach it without
// anyone editing a configuration file or restarting anything.
//
// The name lasts as long as that agent process. Nothing is written to disk on
// either side, which is deliberate: an agent accepts these changes only because
// its operator allowed it, and a change made under that permission should not
// outlive the process that accepted it.
func newExposeCmd(a *app) *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "expose [SERVER] PORT --name NAME",
		Short: "Publish a server's local port under a hostname, for as long as its agent runs",
		Args:  wrapArgs(cobra.RangeArgs(1, 2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExpose(cmd, a, args, name)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "the single label to publish the service as (required)")
	return cmd
}

// runExpose resolves which server is meant, builds the hostname from this
// machine's own naming settings, and relays the request through the daemon.
//
// The name is composed here rather than accepted whole from the user, so it can
// only ever fall inside the zone this machine actually answers for. A name
// outside it would be published on the agent and unreachable from here, with
// nothing to say why.
func runExpose(cmd *cobra.Command, a *app, args []string, label string) error {
	if label == "" {
		return usageErrorf("expose: --name NAME is required; it is the label the service is published as")
	}

	portArg := args[len(args)-1]
	serverArgs := args[:len(args)-1]

	port, err := strconv.Atoi(portArg)
	if err != nil || port < 1 || port > 65535 {
		// Zero is refused rather than read as "choose one for me": nothing here
		// chooses ports, so accepting it would make a typo look like a request
		// for something this cannot do.
		return usageErrorf("expose: %q is not a port between 1 and 65535", portArg)
	}

	serverName, err := autoSelectServer(a, serverArgs)
	if err != nil {
		return err
	}
	if err := requireKnownServer(a, serverName); err != nil {
		return err
	}

	naming, err := a.cfg.Naming()
	if err != nil {
		return fmt.Errorf("naming settings: %w", err)
	}

	// Lowercased before it is checked, published, or printed. Hostnames are
	// compared without regard to case, so accepting a capital and then storing
	// it verbatim would mean the name printed here and the name the agent
	// answers for could differ.
	label = strings.ToLower(label)
	if err := router.ValidateVhostLabel(label); err != nil {
		return usageErrorf("expose: %v", err)
	}
	host := label + "." + serverName + "." + naming.Suffix

	sock, err := daemonSocketPath(a.cfg)
	if err != nil {
		return fmt.Errorf("resolve socket path: %w", err)
	}

	raw, err := ipc.NewClient(sock).ExposeJSON(serverName, host, port)
	if err != nil {
		return relayIPCError(cmd, "expose", err, true)
	}

	var snap daemon.ExposeSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("parse expose response: %w", err)
	}

	// The agent chose what to call this, so it is treated like every other
	// string an agent sends: run through the same cleaning as the route
	// listing before it reaches a terminal.
	publishedHost := sanitizeAgentString(snap.Host)
	if publishedHost == "" {
		publishedHost = host
	}
	fmt.Fprintf(cmd.OutOrStdout(), "url: http://%s:%d\n", publishedHost, snap.HTTPPort)
	return nil
}
