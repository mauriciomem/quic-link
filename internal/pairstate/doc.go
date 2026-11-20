// Package pairstate persists pairing state: the agent's authorized_clients
// file and the client's paired.toml.
//
// authorized_clients holds one client pin per line, optionally followed by
// tags such as state=unconfirmed and a "# comment". Authorization is decided
// solely by the presence of a line whose pin is valid: the state tag is
// forensic only, and an unconfirmed or unknown entry is authorized. No tag
// may restrict access, now or in any future version, because an older reader
// ignores tags it does not know; revocation is deleting the line. A line whose
// pin field does not parse rejects the whole file, so a damaged file is never
// half trusted; nothing else does. Any other irregularity on a line whose pin
// parses - an unknown or malformed tag, a repeated state tag, a CRLF line
// ending, control or non-ASCII bytes in a comment - is tolerated and reported
// as a Note. Text taken from the file is escaped to printable ASCII before it
// reaches a Note, an Entry comment or an error. Writers emit only
// "PIN state=<value>[ # <comment>]" lines and leave every line they do not
// rewrite byte-for-byte.
//
// Every writer of authorized_clients holds an exclusive flock on a sibling
// ".lock" file across its read-modify-write, so concurrent processes cannot
// lose each other's updates. Readers do not lock: the file is only ever
// replaced by an atomic rename.
package pairstate
