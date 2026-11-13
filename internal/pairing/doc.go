// Package pairing holds unwired pairing primitives: the join blob a listener
// hands to a joiner, the HMAC proof bound to the TLS exporter of the pairing
// connection, the pairing request and response messages, and their framing.
//
// Nothing in production imports this package yet; it performs no I/O beyond
// the io.Reader and io.Writer it is given.
package pairing
