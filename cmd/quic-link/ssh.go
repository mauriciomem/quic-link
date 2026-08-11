package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

// sshBinary is the executable name (or path) used to exec the system ssh
// client. It is a package-level var, not a constant, so tests can point it
// at a stub script instead of a real ssh installation.
var sshBinary = "ssh"

// shellQuote returns s wrapped in single quotes, with any embedded single
// quote escaped, so the result is safe to embed literally inside a POSIX
// shell command line. ssh's ProxyCommand is handed to a shell for execution
// (verified: an unquoted absolute path containing spaces fails with a
// bash "No such file or directory" error), so the binary path — and,
// defensively, the --server/--pin values threaded into the config-free
// mode — are quoted with this routine rather than interpolated as bare
// strings. The technique is the standard POSIX close-quote,
// escaped-quote, reopen-quote trick for embedding a literal quote
// character inside a single-quoted string.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// errExecExitCode carries the exit status of a child process quic-link
// exec'd directly (the system ssh binary). Unlike errFinalExitCode, which
// describes an agent or daemon refusal ("attach refused"), this type makes
// no claim about who refused what: the child's exit status is opaque to
// quic-link, ssh may have failed for any reason of its own (bad host key,
// wrong password, a typo in the user's own passthrough flags), and none of
// that involves an agent response. A message borrowed from the attach path
// would misleadingly blame the wrong layer, so this type gets its own,
// deliberately neutral, message.
type errExecExitCode struct {
	code int
}

func (e *errExecExitCode) Error() string {
	return fmt.Sprintf("ssh exited with status %d", e.code)
}

// alreadyReported signals that main() should not print an additional
// slog.Error line: ssh inherits this process's stdin/stdout/stderr directly,
// so any diagnostic ssh itself has to offer was already written to the
// user's terminal by ssh, not by quic-link.
func (e *errExecExitCode) alreadyReported() bool { return true }

func newSSHCmd(a *app) *cobra.Command {
	var (
		serverFlag string
		pinFlag    string
	)

	cmd := &cobra.Command{
		Use:   "ssh [USER@]SERVER [-- ssh-args...]",
		Short: "SSH to a server through quic-link",
		Long: `SSH to a server through quic-link by execing the system ssh binary with a
generated ProxyCommand and HostKeyAlias. No user configuration file is ever
touched: the ProxyCommand is a runtime flag on the ssh process this command
spawns, nothing more.

[USER@]SERVER is passed straight through to ssh unchanged — ssh itself
strips the username before expanding %n, so quic-link only needs to split on
'@' for its own config lookup and for -o HostKeyAlias=<server>.

With no SERVER and no --server/--pin, the sole enabled server in the config
is used automatically (error 2 if the config has more than one). With
--server ADDR --pin PIN, no config file or running daemon is required, but
SERVER becomes a required label (there is no config to default it from):

  quic-link ssh --server 192.0.2.10:443 --pin <agent-pin> alice@server1

Exit code is ssh's own, unlike every other quic-link verb.`,
		// No Args validator: RunE parses args itself using ArgsLenAtDash to
		// separate the optional [USER@]SERVER positional from ssh's own
		// passthrough flags after --, which a canned validator cannot express.
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSH(cmd, a, args, serverFlag, pinFlag)
		},
	}

	cmd.Flags().StringVar(&serverFlag, "server", "", "host:port of the quic-link agent (config-free mode; requires --pin and a SERVER label)")
	cmd.Flags().StringVar(&pinFlag, "pin", "", "expected agent pin (config-free mode; requires --server)")

	return cmd
}

// splitSSHArgs separates the ssh verb's own optional [USER@]SERVER positional
// from ssh's own passthrough arguments, using cmd.ArgsLenAtDash() to find the
// -- boundary cobra/pflag already parsed. It returns a usage error if more
// than one argument appears before the boundary (or before end-of-args, when
// there is no --).
func splitSSHArgs(cmd *cobra.Command, args []string) (serverArg string, passthrough []string, err error) {
	dash := cmd.ArgsLenAtDash()
	if dash == -1 {
		if len(args) > 1 {
			return "", nil, usageErrorf(
				"too many arguments; put ssh's own flags after --, e.g. ssh SERVER -- -v")
		}
		if len(args) == 1 {
			serverArg = args[0]
		}
		return serverArg, nil, nil
	}
	if dash > 1 {
		return "", nil, usageErrorf(
			"too many arguments before --; expected at most one [USER@]SERVER")
	}
	if dash == 1 {
		serverArg = args[0]
	}
	return serverArg, args[dash:], nil
}

// bareServerName strips a "user@" prefix, returning just the server part.
// ssh itself strips everything up to and including the LAST '@' before
// expanding %n — verified against OpenSSH 10.2p1 with a ProxyCommand probe
// printing %n/%r: "alice@server1" gives %n=server1, and a GSSAPI/Kerberos-
// style principal like "alice@REALM@server1" gives %n=server1 with the
// interior '@' kept as part of the username (%r=alice@REALM). Splitting on
// the FIRST '@' instead (Go's strings.Cut) would misparse the multi-'@' case
// as server "REALM@server1", which is wrong for both the config lookup and
// -o HostKeyAlias. Go has no right-hand Cut, so this uses LastIndex.
//
// Edge cases, chosen deliberately:
//   - no '@' at all ("server1"): the whole string is the server, unchanged.
//   - a trailing '@' with nothing after it ("alice@"): returns "", the same
//     honest empty result as an actually-empty input. This function never
//     invents a name to paper over a malformed argument; it is up to the
//     caller to decide what an empty result means (today, runSSHCore
//     treats it the same as "no server was named at all" and falls back to
//     config auto-resolution — that pre-existing fallback behaviour is
//     unchanged by this fix).
//   - a leading '@' ("@server1"): the username part is empty and the
//     server is everything after the '@', matching ssh's own behaviour for
//     the same input.
func bareServerName(serverArg string) string {
	i := strings.LastIndex(serverArg, "@")
	if i == -1 {
		return serverArg
	}
	return serverArg[i+1:]
}

// buildProxyCommand returns the ProxyCommand value passed to ssh via
// -o ProxyCommand=<value>. flagMode selects the config-free form, which
// threads --server/--pin into the generated stdio invocation. configPath, if
// non-empty, threads the parent invocation's explicitly-set --config into
// the same generated command, so the spawned stdio child reads the same
// config file the parent was told to use instead of silently falling back
// to the default path. Callers must pass "" when the user did not
// explicitly set --config; this function does not decide that, it only
// includes what it is given.
//
// The emitted string is deliberately not a contract surface: only
// "no user file touched" and "exit code is ssh's own" are guaranteed to
// hold across releases.
func buildProxyCommand(binPath string, flagMode bool, serverFlag, pinFlag string, configPath string) string {
	prefix := shellQuote(binPath)
	if configPath != "" {
		prefix += " --config " + shellQuote(configPath)
	}
	if flagMode {
		return fmt.Sprintf("%s stdio --server %s --pin %s %%n ssh",
			prefix, shellQuote(serverFlag), shellQuote(pinFlag))
	}
	return fmt.Sprintf("%s stdio %%n ssh", prefix)
}

// runSSH is the ssh verb's implementation. It parses this command's own args
// into a [USER@]SERVER positional plus passthrough flags, then delegates the
// rest of the work — resolving the server, building the ProxyCommand, and
// exec'ing ssh — to runSSHCore, which attach also calls directly so there is
// no duplicated ssh-invocation logic anywhere in the tree.
func runSSH(cmd *cobra.Command, a *app, args []string, serverFlag, pinFlag string) error {
	flags := cmd.Flags()

	serverArg, passthrough, err := splitSSHArgs(cmd, args)
	if err != nil {
		return err
	}

	flagMode := flags.Changed("server") || flags.Changed("pin")
	if flagMode && !(flags.Changed("server") && flags.Changed("pin")) {
		return usageErrorf("--server and --pin must be given together")
	}

	return runSSHCore(cmd, a, serverArg, passthrough, flagMode, serverFlag, pinFlag)
}

// runSSHCore builds the ProxyCommand and execs the system ssh binary. It is
// the single implementation shared by both the ssh verb and attach (pure
// sugar that calls this directly with a synthesized passthrough), so a fix
// or a behaviour change here applies to both with no duplicated logic.
//
// serverArg is the raw [USER@]SERVER token as it will be passed to ssh
// itself (unchanged); passthrough are ssh's own extra arguments, inserted
// between the quic-link-generated -o flags and serverArg. flagMode selects
// the config-free path (SERVER is then required as a label, not resolved
// from config).
func runSSHCore(cmd *cobra.Command, a *app, serverArg string, passthrough []string, flagMode bool, serverFlag, pinFlag string) error {
	bareServer := bareServerName(serverArg)

	if bareServer == "" {
		if flagMode {
			return usageErrorf(
				"SERVER is required as a label when --server/--pin are given " +
					"(there is no config to default it from)")
		}
		name, rerr := autoSelectServer(a, nil)
		if rerr != nil {
			return rerr
		}
		bareServer = name
		serverArg = name // no username was given; ssh needs an actual host argument
	}

	if !flagMode {
		// Both checks below happen before ssh is exec'd, and that ordering is
		// the whole point of doing them here. Once ssh runs, its ProxyCommand
		// failure surfaces from inside a child process as a generic connection
		// error, so a name nobody knows or a server switched off would reach the
		// user with none of the remedy either one has.
		if err := requireKnownServer(a, bareServer); err != nil {
			return err
		}
		// A disabled server is not a usage error (the name resolved); it is a
		// state meaning the session is unavailable, so it exits 3 with the
		// remedy. Message and exit code match stdio's identical check exactly so
		// the two verbs agree. Only settings can say "disabled" — a server the
		// daemon manages is by definition not switched off — so this reads the
		// file when it has an entry and is silent when it does not.
		if srv, inFile := a.cfg.Servers[bareServer]; inFile && srv.Enabled != nil && !*srv.Enabled {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"server %q is disabled; set enabled = true in the config to use it\n",
				bareServer)
			return &errFinalExitCode{
				code: 3,
				msg:  fmt.Sprintf("server %q is disabled", bareServer),
			}
		}
	}

	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve quic-link's own executable path: %w", err)
	}

	// Only thread --config through when the user actually set it on this
	// invocation. --config is a persistent flag on the root command, so
	// cmd.Flags().Changed reads it via the same shared flag object that
	// PersistentPreRunE already parsed — cobra passes the full argument
	// list (including flags that precede the subcommand name) down to the
	// leaf command's own flag parse, and mergePersistentFlags folds the
	// root's persistent flags into the leaf's FlagSet by reference, not by
	// copy, so this Changed() check is exactly as reliable as the
	// --server/--pin checks already used above. A default (unset) config
	// path must never be synthesized here: that would hardcode a resolved
	// path into the ProxyCommand and change behaviour for the common case
	// of relying on the default location.
	var configPath string
	if cmd.Flags().Changed("config") {
		configPath = a.configPath
	}

	proxyCommand := buildProxyCommand(binPath, flagMode, serverFlag, pinFlag, configPath)

	sshPath, err := exec.LookPath(sshBinary)
	if err != nil {
		return fmt.Errorf("ssh binary not found in PATH: %w", err)
	}

	// Real ssh's grammar is "ssh [options] destination [command]": the
	// destination must precede any passthrough, or a remote command in the
	// passthrough (attach's synthesized "tmux attach -t SESSION", or a
	// user's own "-- ... echo hi") gets misparsed as the destination and
	// everything meant as the destination gets misparsed as part of the
	// command instead. Placing the destination first is safe: OpenSSH
	// permutes its own -o/-t/etc. flags appearing after the destination
	// (verified against OpenSSH 10.2p1), so ssh's own passthrough flags
	// still work exactly as before, immediately after the destination.
	sshArgs := make([]string, 0, len(passthrough)+5)
	sshArgs = append(sshArgs,
		"-o", "ProxyCommand="+proxyCommand,
		"-o", "HostKeyAlias="+bareServer,
	)
	sshArgs = append(sshArgs, serverArg)
	sshArgs = append(sshArgs, passthrough...)

	child := exec.CommandContext(cmd.Context(), sshPath, sshArgs...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr

	runErr := child.Run()
	if runErr == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return &errExecExitCode{code: exitErr.ExitCode()}
	}
	// ssh never actually started (e.g. permission denied) — not "ssh's own"
	// exit code, so this falls through exitCodeForError's default case.
	return fmt.Errorf("exec ssh: %w", runErr)
}
