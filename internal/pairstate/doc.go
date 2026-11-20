// Package pairstate persists pairing state: the agent's authorized_clients
// file and the client's paired.toml.
//
// authorized_clients holds one client pin per line, optionally followed by
// tags such as state=unconfirmed and a "# comment". Authorization is decided
// solely by the presence of a line whose pin is valid: the state tag is
// forensic only, and an unconfirmed or unknown entry is authorized. No tag
// may restrict access, now or in any future version, because an older reader
// ignores tags it does not know; revocation is deleting the line. A line whose
// pin does not parse rejects the whole file, so a damaged file is never half
// trusted.
//
// Every writer of authorized_clients holds an exclusive flock on a sibling
// ".lock" file across its read-modify-write, so concurrent processes cannot
// lose each other's updates. Readers do not lock: the file is only ever
// replaced by an atomic rename.
package pairstate
