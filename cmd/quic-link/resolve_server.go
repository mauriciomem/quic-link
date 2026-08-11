package main

import (
	"encoding/json"
	"errors"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

// knownServers reports the server names a command may legitimately be given,
// asking the running daemon first and falling back to the settings file.
//
// The two answers are not the same question. Settings say which servers a user
// has DEFINED; the daemon says which ones are actually being MANAGED right now,
// and those diverge as soon as a server can be defined on a command line: such
// a server exists only in the memory of the process that was given the flags,
// so a second command has no file to read it from and must ask the process.
//
// Asking the daemon and falling back is what lets both ways of running work.
// With a daemon up, a name it manages is accepted whatever created it. With no
// daemon, the settings file answers exactly as it always did, so nothing about
// working from a file changes.
//
// ok is false when neither source could be consulted, which is different from
// an empty answer: a caller must not conclude "no such server" from a question
// nobody could answer.
func knownServers(a *app) (names map[string]struct{}, fromDaemon bool, ok bool) {
	if sock, err := daemonSocketPath(a.cfg); err == nil {
		if raw, rerr := ipc.NewClient(sock).StatusJSON(); rerr == nil {
			var snap daemon.StatusSnapshot
			if json.Unmarshal(raw, &snap) == nil {
				names = make(map[string]struct{}, len(snap.Servers))
				for _, srv := range snap.Servers {
					names[srv.Name] = struct{}{}
				}
				return names, true, true
			}
		} else if !errors.Is(rerr, ipc.ErrDaemonAbsent) && !errors.Is(rerr, ipc.ErrSchemaMismatch) {
			// The socket answered something unexpected. Fall through to the
			// settings file rather than treating an unreadable daemon as proof
			// that a server does not exist.
			_ = rerr
		}
	}

	if len(a.cfg.Servers) == 0 {
		return nil, false, false
	}
	names = make(map[string]struct{}, len(a.cfg.Servers))
	for name := range a.cfg.Servers {
		names[name] = struct{}{}
	}
	return names, false, true
}

// requireKnownServer checks that name is a server this machine can act on, and
// explains the answer in the terms of whichever source answered.
//
// The wording matters more than it looks. Telling somebody a server is "not
// found in config" when a daemon is managing it under that very name sends them
// to edit a file that is not the problem — and when the server was defined on a
// command line, there is no file to edit at all.
func requireKnownServer(a *app, name string) error {
	names, fromDaemon, ok := knownServers(a)
	if !ok {
		return usageErrorf(
			"no servers are defined: add a [servers.<name>] entry to %s, or give one to "+
				"'quic-link daemon' on the command line",
			config.FileInUse(a.configPath))
	}
	if _, found := names[name]; found {
		return nil
	}
	if fromDaemon {
		return usageErrorf("server %q is not managed by the running daemon; it manages %s",
			name, serverNameList(namesAsServers(names)))
	}
	return usageErrorf("server %q not found in config; available servers: %s",
		name, serverNameList(namesAsServers(names)))
}

// namesAsServers adapts a set of names to the shape serverNameList reads, so
// that one wording of "available servers" is used everywhere.
func namesAsServers(names map[string]struct{}) map[string]config.Server {
	out := make(map[string]config.Server, len(names))
	for n := range names {
		out[n] = config.Server{}
	}
	return out
}

// autoSelectServer picks the server a client verb should act on when the user
// named none, asking the running daemon first and falling back to settings.
//
// It is separate from the scope resolution the owner verb uses, and the split is
// deliberate: the owner is about to BUILD a fleet, so only settings can tell it
// what to build, while a client verb acts on a fleet that already exists and
// should therefore ask what is really there. Sharing one function would force
// one of the two to answer the wrong question.
//
// With one server, that server is used. With several, the user is asked to name
// one, because guessing would silently act on something they did not choose.
func autoSelectServer(a *app, args []string) (string, error) {
	if len(args) == 1 {
		return args[0], nil
	}

	names, fromDaemon, ok := knownServers(a)
	if !ok || len(names) == 0 {
		return "", usageErrorf(
			"no SERVER given and none is available; add a [servers.<name>] entry to %s, "+
				"or start 'quic-link daemon' with server flags",
			config.FileInUse(a.configPath))
	}
	if len(names) == 1 {
		for n := range names {
			return n, nil
		}
	}

	where := "in your settings"
	if fromDaemon {
		where = "managed by the running daemon"
	}
	return "", usageErrorf("no SERVER given and %d servers are %s; name one\n  available: %s",
		len(names), where, serverNameList(namesAsServers(names)))
}
