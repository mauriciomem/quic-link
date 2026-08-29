package daemon

// DisableCoreDump exports disableCoreDump so a caller outside package daemon
// can disable core dumps before it loads its own copy of the Ed25519
// identity key. Two call sites outside this package use it by design, not
// by accident: the CLI's agent verb (cmd/quic-link/agent.go, through the
// disableCoreDumpFunc seam) and the daemon owner verb
// (cmd/quic-link/daemoncmd.go's runDaemonOwner, directly), both calling it
// as their first statement so the key load and session dial that follow
// never run with core dumps still enabled. daemon.Run also calls
// disableCoreDump for its own startup path — a third, harmless call, since
// the resource limit is already at zero by the time any of the others run
// it again. This wrapper lets every one of them reach the exact same
// build-tagged implementation (coredump_unix.go / coredump_other.go) rather
// than duplicating it, so there is exactly one place that knows how to lower
// RLIMIT_CORE on each platform.
//
// The error is returned rather than logged here: each caller knows its own
// role name ("agent" vs "daemon") for the log line, and logging it here as
// well would duplicate or risk diverging from that.
func DisableCoreDump() error {
	return disableCoreDump()
}
