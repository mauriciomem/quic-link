package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/buildinfo"
	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/names"
	"github.com/mauriciomem/quic-link/internal/setup"
)

// report is what doctor found. It is assembled from three places — this
// machine's filesystem, this machine's resolver, and the running daemon — and
// every one of them is optional, because the moment a person most wants this
// verb is when one of them is missing.
type report struct {
	Schema  int    `json:"schema"`
	Version string `json:"version"`
	Suffix  string `json:"suffix"`
	// ConfigError is set when the settings cannot be used. The rest of the
	// report is still filled in: this verb exists for the times something is
	// wrong, so one bad value must not take the rest of the answer away.
	ConfigError string          `json:"config_error,omitempty"`
	Resolver    resolverReport  `json:"resolver"`
	Artifacts   []artifactJSON  `json:"artifacts"`
	Daemon      *daemonReport   `json:"daemon,omitempty"`
	Resolution  resolutionCheck `json:"resolution"`
	NextStep    string          `json:"next_step,omitempty"`
}

type resolverReport struct {
	Kind      string `json:"kind"`
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
}

type artifactJSON struct {
	Path    string `json:"path"`
	Scope   string `json:"scope"`
	Present bool   `json:"present"`
	Ours    bool   `json:"ours"`
	Current bool   `json:"current"`
	Purpose string `json:"purpose,omitempty"`
}

type daemonReport struct {
	Running   bool     `json:"running"`
	DNSPort   int      `json:"dns_port,omitempty"`
	HTTPPort  int      `json:"http_port,omitempty"`
	HTTPSPort int      `json:"https_port,omitempty"`
	Servers   []string `json:"servers,omitempty"`
}

// resolutionCheck records both halves of the question. An address coming back
// is not proof: a cache, a hosts entry, or a wildcard somewhere else would all
// produce one. Only the responder having been asked proves the machine's
// resolver is pointed here.
type resolutionCheck struct {
	Name      string `json:"name"`
	Answered  bool   `json:"answered"`
	Address   string `json:"address,omitempty"`
	ReachedUs bool   `json:"reached_responder"`
	Note      string `json:"note,omitempty"`
}

func newDoctorCmd(a *app) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:          "doctor",
		Short:        "Report what is set up on this machine, and what is not",
		Long:         `Look at this machine and say plainly what is in place, what is missing, and the one thing to do next. Changes nothing.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := diagnose(cmd, a)
			if asJSON {
				b, err := json.Marshal(r)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}
			writeReport(cmd.OutOrStdout(), r)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return cmd
}

func diagnose(cmd *cobra.Command, a *app) report {
	r := report{Schema: 1, Version: buildinfo.Version()}

	// A bad setting is reported and then stepped over. Returning here would
	// mean that the one situation this verb is for — something is wrong — is
	// the situation in which it says the least.
	n, nerr := a.cfg.Naming()
	if nerr != nil {
		r.Suffix = "(unusable)"
		r.ConfigError = nerr.Error()
	} else {
		r.Suffix = n.Suffix
	}

	res := setup.DetectResolver(cmd.Context())
	r.Resolver = resolverReport{
		Kind:      res.Support.String(),
		Supported: res.Support != setup.Unsupported,
		Reason:    res.Reason,
	}

	home, _ := os.UserHomeDir()
	var arts []setup.Artifact
	if nerr == nil {
		// Which system file we would write depends on the suffix, so with an
		// unusable one there is no particular file to look for.
		arts = setup.Survey(setup.Inventory(n.Suffix, n.DNSPort))
	}
	if home != "" {
		arts = append(arts, setup.Survey(setup.UserPaths(
			expandTilde(a.cfg.Identity.KeyFile),
			config.FileInUse(a.configPath)))...)
	}
	for _, art := range arts {
		r.Artifacts = append(r.Artifacts, artifactJSON{
			Path: art.Path, Scope: art.Scope.String(), Present: art.Present,
			Ours: art.Ours, Current: art.Current, Purpose: art.Purpose,
		})
	}

	// The check is a fresh name every time. A fixed one would be cached after
	// the first run and every later run would report a responder that was never
	// asked, which is exactly backwards.
	var probe string
	if nerr == nil {
		var nonce [6]byte
		_, _ = rand.Read(nonce[:])
		probe = hex.EncodeToString(nonce[:])
		canary := probe + "." + names.ProbeLabel + "." + n.Suffix
		r.Resolution = resolutionCheck{Name: canary}

		addrs, lerr := lookupThroughSystem(canary)
		if lerr == nil && len(addrs) > 0 {
			r.Resolution.Answered = true
			r.Resolution.Address = addrs[0]
		}
	} else {
		r.Resolution.Note = "not attempted: there is no usable suffix to ask about"
	}

	if d, ok := askDaemon(a, probe); ok {
		r.Daemon = &daemonReport{
			Running: true, DNSPort: d.DNSPort, HTTPPort: d.HTTPPort,
			HTTPSPort: d.HTTPSPort, Servers: d.Servers,
		}
		r.Resolution.ReachedUs = d.ProbeSeen
		if r.Resolution.Answered && !d.ProbeSeen {
			r.Resolution.Note = "a name resolved, but the query never reached this machine's " +
				"responder — something else answered it"
		}
	} else {
		r.Daemon = &daemonReport{Running: false}
		r.Resolution.Note = "no daemon is running, so nothing could answer"
	}

	r.NextStep = nextStep(r, res)
	return r
}

// lookupThroughSystem asks for a name the way an ordinary program would.
func lookupThroughSystem(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, name)
}

func askDaemon(a *app, probe string) (daemon.DoctorSnapshot, bool) {
	var out daemon.DoctorSnapshot
	sock, err := daemonSocketPath(a.cfg)
	if err != nil {
		return out, false
	}
	body, err := ipc.NewClient(sock).DoctorJSON(probe)
	if err != nil {
		return out, false
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, false
	}
	return out, true
}

// nextStep picks the single most useful thing to do, working up from the most
// fundamental. Listing everything that is wrong at once leaves a person to work
// out the order themselves, and the order is always the same.
func nextStep(r report, res setup.Resolver) string {
	// Nothing else can be acted on until the settings can be read.
	if r.ConfigError != "" {
		return "fix your settings: " + r.ConfigError
	}
	for _, a := range r.Artifacts {
		if a.Scope == "user" && a.Purpose == "this machine's identity" && !a.Present {
			return "make this machine an identity: quic-link keygen"
		}
	}
	// Settings come after an identity because a file naming servers is no use
	// without a key to reach them with. Saying nothing here used to leave the
	// one person who most needs an answer — somebody with no settings at all —
	// reading a report that listed the file as absent and then moved on.
	for _, a := range r.Artifacts {
		if a.Scope == "user" && a.Purpose == "your settings" && !a.Present {
			return "write your settings, naming at least one server:\n" +
				"    [servers.<name>]\n" +
				"    addr = \"host:port\"\n" +
				"    pin  = \"<the agent's pin>\"\n" +
				"  in " + a.Path
		}
	}
	if !r.Resolver.Supported {
		return "names cannot be registered on this machine; set it up by hand:\n" + res.Manual
	}
	for _, a := range r.Artifacts {
		if a.Scope == "root" && (!a.Present || !a.Current) {
			return "register names with this machine's resolver: sudo quic-link init"
		}
	}
	if r.Daemon == nil || !r.Daemon.Running {
		return "start the daemon: quic-link daemon"
	}
	if !r.Resolution.ReachedUs {
		return "names are registered and the daemon is running, but a test lookup did not\n" +
			"reach it. Reload your resolver, or check what else is answering for " + r.Suffix
	}
	return ""
}

func writeReport(w io.Writer, r report) {
	fmt.Fprintf(w, "quic-link %s\n\n", r.Version)
	fmt.Fprintf(w, "Names\n")
	fmt.Fprintf(w, "  suffix            %s\n", r.Suffix)
	if r.ConfigError != "" {
		fmt.Fprintf(w, "                    %s\n", wrap(r.ConfigError, 60, "                    "))
	}
	fmt.Fprintf(w, "  this machine      %s\n", r.Resolver.Kind)
	if r.Resolver.Reason != "" {
		fmt.Fprintf(w, "                    %s\n", wrap(r.Resolver.Reason, 60, "                    "))
	}

	fmt.Fprintf(w, "\nDaemon\n")
	if r.Daemon != nil && r.Daemon.Running {
		fmt.Fprintf(w, "  running           yes\n")
		if r.Daemon.DNSPort > 0 {
			fmt.Fprintf(w, "  answering on      127.0.0.1:%d for names\n", r.Daemon.DNSPort)
		}
		if r.Daemon.HTTPPort > 0 {
			fmt.Fprintf(w, "                    127.0.0.1:%d for web requests\n", r.Daemon.HTTPPort)
		}
		if r.Daemon.HTTPSPort > 0 {
			fmt.Fprintf(w, "                    127.0.0.1:%d for secure web requests\n", r.Daemon.HTTPSPort)
		}
		if len(r.Daemon.Servers) > 0 {
			fmt.Fprintf(w, "  serving names for %v\n", r.Daemon.Servers)
		}
	} else {
		fmt.Fprintf(w, "  running           no\n")
	}

	fmt.Fprintf(w, "\nFiles quic-link has put on this machine\n")
	for _, a := range r.Artifacts {
		state := "absent"
		switch {
		case a.Present && a.Ours && a.Current:
			state = "in place"
		case a.Present && a.Ours:
			state = "out of date"
		case a.Present:
			state = "not ours"
		}
		fmt.Fprintf(w, "  %-12s %-6s %s\n", state, a.Scope, a.Path)
	}

	fmt.Fprintf(w, "\nTest lookup\n")
	if r.Resolution.Name == "" {
		fmt.Fprintf(w, "  not attempted     %s\n", r.Resolution.Note)
	} else {
		fmt.Fprintf(w, "  asked for         %s\n", r.Resolution.Name)
	}
	switch {
	case r.Resolution.Name == "":
		// nothing to report
	case r.Resolution.ReachedUs:
		fmt.Fprintf(w, "  result            answered by this machine's responder\n")
	case r.Resolution.Answered:
		fmt.Fprintf(w, "  result            answered, but not by us\n")
	default:
		fmt.Fprintf(w, "  result            no answer\n")
	}
	if r.Resolution.Note != "" && r.Resolution.Name != "" {
		fmt.Fprintf(w, "                    %s\n", wrap(r.Resolution.Note, 60, "                    "))
	}

	if r.NextStep != "" {
		fmt.Fprintf(w, "\nNext step\n  %s\n", r.NextStep)
	} else {
		fmt.Fprintf(w, "\nEverything is set up.\n")
	}
}
