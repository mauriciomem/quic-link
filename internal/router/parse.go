package router

// ParseAddr converts a route address string to the (network, address) pair
// used by net.Dial. It accepts "tcp://host:port" and "unix:///absolute/path";
// any other scheme returns an error. The implementation delegates to the
// unexported parseAddr so this function and the internal route-table builder
// share one code path and cannot diverge.
func ParseAddr(raw string) (network, address string, err error) {
	return parseAddr(raw)
}
