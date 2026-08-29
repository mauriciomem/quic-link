package daemon

// DisableCoreDump exports disableCoreDump so a caller outside package daemon
// (the CLI's agent verb) can disable core dumps before it loads its own copy
// of the Ed25519 identity key. Run already calls disableCoreDump for the
// daemon's own startup path; this wrapper lets the agent reach the exact same
// build-tagged implementation (coredump_unix.go / coredump_other.go) rather
// than duplicating it, so there is exactly one place that knows how to lower
// RLIMIT_CORE on each platform.
//
// The error is returned rather than logged here: the caller knows its own
// role name ("agent" vs "daemon") for the log line, and Run already has its
// own Warn call for the daemon side that this must not duplicate or diverge
// from.
func DisableCoreDump() error {
	return disableCoreDump()
}
