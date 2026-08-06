package names

import "errors"

// ErrNoSNI means the handshake named no host, so there is nothing to route on.
var ErrNoSNI = errors.New("names: the handshake names no host")

// SNIFromClientHello finds the host a TLS client asked for.
//
// It returns need=true when the bytes so far are a valid but unfinished start
// of a handshake and more should be read. Every length in the input belongs to
// the client, so each one is checked against what is actually there before it
// is used — a length is a claim, not a fact.
//
// Only enough of the handshake is read to find the name. Nothing is decrypted,
// nothing is answered, and the bytes are passed on untouched, so the service at
// the far end completes the handshake with the client itself and this never
// becomes a party to it.
func SNIFromClientHello(buf []byte) (host string, need bool, err error) {
	// A record: type, version, length.
	if len(buf) < 5 {
		return "", true, nil
	}
	if buf[0] != 0x16 { // handshake
		return "", false, ErrMalformed
	}
	// One handshake message may be split across records, so gather the
	// fragments before looking inside.
	var hs []byte
	rest := buf
	for len(rest) >= 5 {
		if rest[0] != 0x16 {
			return "", false, ErrMalformed
		}
		n := int(rest[3])<<8 | int(rest[4])
		if n == 0 || n > 1<<14 {
			return "", false, ErrMalformed
		}
		if len(rest) < 5+n {
			return "", true, nil // the record is still arriving
		}
		hs = append(hs, rest[5:5+n]...)
		rest = rest[5+n:]
		if len(hs) > MaxHeaderBytes {
			return "", false, ErrMalformed
		}
		// Stop once the handshake message is complete.
		if len(hs) >= 4 {
			want := 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
			if len(hs) >= want {
				hs = hs[:want]
				break
			}
		}
	}
	if len(hs) < 4 {
		return "", true, nil
	}
	if hs[0] != 0x01 { // client_hello
		return "", false, ErrMalformed
	}
	body := hs[4:]
	if want := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]); len(body) < want {
		return "", true, nil
	}

	r := reader{b: body}
	if !r.skip(2 + 32) { // version, random
		return "", true, nil
	}
	if !r.skipVec(1) { // session id
		return "", true, nil
	}
	if !r.skipVec(2) { // cipher suites
		return "", true, nil
	}
	if !r.skipVec(1) { // compression methods
		return "", true, nil
	}
	ext, ok := r.vec(2)
	if !ok {
		// No extension block at all: an old client, with no name to give.
		return "", false, ErrNoSNI
	}

	e := reader{b: ext}
	for {
		typ, ok := e.u16()
		if !ok {
			return "", false, ErrNoSNI
		}
		data, ok := e.vec(2)
		if !ok {
			return "", false, ErrMalformed
		}
		if typ != 0 { // server_name
			continue
		}
		dr := reader{b: data}
		list, ok := dr.vec(2)
		if !ok {
			return "", false, ErrMalformed
		}
		l := reader{b: list}
		var found string
		for {
			kind, ok := l.u8()
			if !ok {
				break
			}
			name, ok := l.vec(2)
			if !ok {
				return "", false, ErrMalformed
			}
			if kind != 0 { // host_name
				continue
			}
			if found != "" {
				// Two names is two answers about where this is going.
				return "", false, ErrAmbiguousHost
			}
			found = string(name)
		}
		if found == "" {
			return "", false, ErrNoSNI
		}
		return found, false, nil
	}
}

// reader walks a byte slice, refusing to read past its end.
type reader struct{ b []byte }

func (r *reader) skip(n int) bool {
	if n < 0 || len(r.b) < n {
		return false
	}
	r.b = r.b[n:]
	return true
}

func (r *reader) u8() (int, bool) {
	if len(r.b) < 1 {
		return 0, false
	}
	v := int(r.b[0])
	r.b = r.b[1:]
	return v, true
}

func (r *reader) u16() (int, bool) {
	if len(r.b) < 2 {
		return 0, false
	}
	v := int(r.b[0])<<8 | int(r.b[1])
	r.b = r.b[2:]
	return v, true
}

// vec reads a length-prefixed block whose length occupies sizeLen bytes.
func (r *reader) vec(sizeLen int) ([]byte, bool) {
	var n int
	switch sizeLen {
	case 1:
		v, ok := r.u8()
		if !ok {
			return nil, false
		}
		n = v
	case 2:
		v, ok := r.u16()
		if !ok {
			return nil, false
		}
		n = v
	default:
		return nil, false
	}
	if len(r.b) < n {
		return nil, false
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out, true
}

func (r *reader) skipVec(sizeLen int) bool {
	_, ok := r.vec(sizeLen)
	return ok
}
