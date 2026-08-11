package names

import (
	"bytes"
	"errors"
	"net"
	"strings"
)

// Errors from reading the name out of a request. They are distinguished so a
// caller can say something useful, and so a test can tell "we refused for the
// right reason" from "we refused by luck".
var (
	ErrNoHost        = errors.New("names: the request names no host")
	ErrAmbiguousHost = errors.New("names: the request names more than one host")
	ErrMalformed     = errors.New("names: the request is not well formed")
	ErrHostIsAddress = errors.New("names: the host is an address, not a name")
	ErrOutsideZone   = errors.New("names: the host is outside this machine's zone")
	ErrNoSuchServer  = errors.New("names: no server of that name is managed here")
)

// MaxHeaderBytes is how much of a request we will read while looking for the
// name. A request that has not finished its headers by then is not one we can
// route, and continuing to buffer would be someone else's decision about how
// much memory we spend.
const MaxHeaderBytes = 16 << 10

// HeaderEnd returns where the header block ends in buf, or -1 if it has not
// ended yet. Reading must continue to this point even after the host has been
// seen, because a second host further down is the ambiguity we have to refuse
// and stopping early would be a way to hide one.
func HeaderEnd(buf []byte) int {
	if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
		return i + 4
	}
	return -1
}

// HostFromRequest reads the host out of a complete HTTP/1.x header block.
//
// It does not tolerate ambiguity anywhere. A request that names a host twice,
// or names one in its request line that disagrees with its Host header, is
// refused rather than resolved in the reader's favour — because the machine at
// the other end may resolve it in the other direction, and a routing decision
// that two parties can disagree about is a routing decision that can be
// steered.
func HostFromRequest(header []byte) (string, error) {
	// A request that carries bytes no request may carry is not one we will
	// make sense of the same way anything else does.
	if bytes.IndexByte(header, 0) >= 0 {
		return "", ErrMalformed
	}

	lines, err := splitHeaderLines(header)
	if err != nil {
		return "", err
	}
	if len(lines) == 0 {
		return "", ErrMalformed
	}

	// The request line. An absolute target carries its own authority, and the
	// far end is required to prefer it over the Host header — so if the two
	// disagree we would route by one while the far end answers for the other.
	lineHost, err := hostFromRequestLine(lines[0])
	if err != nil {
		return "", err
	}

	var found string
	var count int
	for _, l := range lines[1:] {
		name, value, ok := bytes.Cut(l, []byte(":"))
		if !ok {
			return "", ErrMalformed
		}
		// Field names are compared without regard to case, so a second host
		// spelled differently is still a second host.
		if !strings.EqualFold(string(bytes.TrimSpace(name)), "host") {
			continue
		}
		count++
		found = string(bytes.TrimSpace(value))
	}

	switch {
	case count > 1:
		return "", ErrAmbiguousHost
	case count == 0 && lineHost == "":
		return "", ErrNoHost
	case count == 1 && lineHost != "" && !strings.EqualFold(lineHost, found):
		return "", ErrAmbiguousHost
	case count == 0:
		found = lineHost
	}
	if found == "" {
		return "", ErrNoHost
	}
	return found, nil
}

// splitHeaderLines cuts a header block into its lines, refusing the shapes that
// let two readers see different headers: a bare carriage return, and a line
// that continues the one before it.
func splitHeaderLines(header []byte) ([][]byte, error) {
	body := header
	if i := bytes.Index(body, []byte("\r\n\r\n")); i >= 0 {
		body = body[:i]
	}
	var out [][]byte
	for len(body) > 0 {
		i := bytes.Index(body, []byte("\r\n"))
		var line []byte
		if i < 0 {
			line, body = body, nil
		} else {
			line, body = body[:i], body[i+2:]
		}
		// A line starting with space or tab continues the previous one. The
		// practice is long deprecated, readers disagree about it, and we could
		// not rewrite it anyway without changing the bytes we promised to pass
		// through untouched.
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			return nil, ErrMalformed
		}
		// A carriage return anywhere but the line ending, or a newline on its
		// own, means two readers may disagree about where this line ends.
		if bytes.IndexByte(line, '\r') >= 0 || bytes.IndexByte(line, '\n') >= 0 {
			return nil, ErrMalformed
		}
		out = append(out, line)
	}
	return out, nil
}

// hostFromRequestLine returns the authority named by the request line, if it
// names one at all. An ordinary request line names a path and returns "".
func hostFromRequestLine(line []byte) (string, error) {
	parts := bytes.Fields(line)
	if len(parts) != 3 {
		return "", ErrMalformed
	}
	target := string(parts[1])
	switch {
	case target == "*":
		// A request about the server itself rather than a resource on it.
		return "", nil
	case strings.HasPrefix(target, "/"):
		return "", nil
	}
	// Anything else is an absolute or authority form, both of which carry a
	// host we must reconcile with the Host header.
	rest := target
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", ErrMalformed
	}
	return rest, nil
}

// NormalizeHost turns a host as written into the form everything else compares
// against: lowercase, no port, no trailing dot.
//
// The order is not a matter of taste. A browser told to use a port puts that
// port in the host it sends, so a name checked before the port is removed does
// not end in the suffix and every honest request is refused. The obvious cure
// for that symptom — asking whether the name merely contains the suffix — is
// what reopens the hole the check exists to close.
func NormalizeHost(raw string) (string, error) {
	h := strings.TrimSpace(raw)
	if h == "" {
		return "", ErrNoHost
	}
	// A host may not carry credentials; something that does is not a host.
	if strings.ContainsAny(h, "@ \t") {
		return "", ErrMalformed
	}
	// A bracketed host is an address written the only way an address with a
	// port can be written, so it is an address whether or not a port follows.
	if strings.HasPrefix(h, "[") {
		return "", ErrHostIsAddress
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		port := h[i+1:]
		h = h[:i]
		if h == "" {
			return "", ErrNoHost
		}
		for _, c := range port {
			if c < '0' || c > '9' {
				return "", ErrMalformed
			}
		}
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" {
		return "", ErrNoHost
	}
	// An address is not a name and cannot be in any zone. Refusing it is what
	// stops a request that reached us by address from being treated as one that
	// reached us by name.
	if net.ParseIP(h) != nil {
		return "", ErrHostIsAddress
	}
	for _, label := range strings.Split(h, ".") {
		if !dnsLabelBytes(label) {
			return "", ErrMalformed
		}
	}
	return h, nil
}

// ValidLabel reports whether s can be one part of a hostname: one to
// sixty-three bytes of lowercase letters, digits and dashes, not starting or
// ending with a dash.
//
// It is exported so that everything deciding whether a name may enter the
// naming plane agrees with the code that finally has to serve it. Configuration
// validation and the agent's hostname keys ask this rather than restating the
// rule: three copies of one rule drift apart, and a name accepted by an earlier
// check but refused by this one resolves and then cannot be served, which is
// the worst of both answers. A caller wanting its own error message checks this
// and writes one; what counts as a legal label must not differ between callers.
//
// A short token an operator picks for a route is deliberately NOT this rule.
// That one allows characters a hostname may not, and lives with the router.
func ValidLabel(s string) bool { return dnsLabelBytes(s) }

// dnsLabelBytes reports whether s can be one part of a hostname.
func dnsLabelBytes(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// Route works out which server a request is for, refusing anything that is not
// this machine's business.
//
// This is the whole of the check that stops a page on the internet from
// reaching these tunnels: a browser told to fetch a name we do not serve sends
// that name, and a name we do not serve is refused before anything is opened.
func (z *Zone) Route(rawHost string) (server, service, host string, err error) {
	h, err := NormalizeHost(rawHost)
	if err != nil {
		return "", "", "", err
	}
	if !z.InSuffix(h) {
		return "", "", "", ErrOutsideZone
	}
	server, service, ok := z.Split(h)
	if !ok {
		return "", "", "", ErrOutsideZone
	}
	// Ask whether this machine actually looks after that server, which the
	// answer given over DNS for the same name already asks. Without this a
	// name shaped like a hostname but naming nothing is carried further in,
	// and the request fails later against a session that was never going to
	// exist — reported as a missing session rather than a name nobody serves.
	// The set of managed servers is fixed when the zone is built, so a name
	// refused here was never going to be served by this process.
	if !z.Manages(server) {
		return "", "", "", ErrNoSuchServer
	}
	return server, service, h, nil
}
