// Package pairing holds the unwired primitives of the quic-link pairing
// protocol (RFC 001): the join blob a listener hands to a joiner, and the
// HMAC proof bound to the TLS exporter of the pairing connection.
//
// Nothing in production imports this package yet; it performs no I/O.
package pairing
