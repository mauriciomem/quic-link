// Package pairing holds the pairing primitives and the listener-side pieces
// built on them.
//
// The primitives are the join blob a listener hands to a joiner, the HMAC
// proof bound to the TLS exporter of the pairing connection, the pairing
// request and response messages, and their framing.
//
// OpenWindow opens a single-use pairing window holding a one-time secret and
// a deadline. Failed proofs are budgeted per source, and any close wipes the
// secret. NewRoutedListener wraps a transport listener: Accept returns only
// connections that negotiated the steady protocol, a pairing connection goes
// to the handler, within a cap overall and per source, and anything else is
// closed. Serve is that handler: it reads one request on one connection, lets
// the window judge it, and saves an admitted pin through a Persister before
// answering ok.
//
// Nothing in production imports this package yet.
package pairing
