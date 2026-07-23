package config

import (
	"crypto/sha256"
	"encoding/binary"
)

// LocalPortBase returns the deterministic base port for a server name.
// The formula is:
//
//	42000 + 10 * (binary.BigEndian.Uint16(sha256("quic-link-v1:"+name)[0:2]) % 2000)
//
// This places every server in the range [42000, 61990] with 10-port strides,
// giving 2000 possible slots and 8 ports of space between neighbours for
// future per-server services. The result is stable across restarts: the same
// name always yields the same port. The +10 clash-probe (bind; retry at
// base+10 if bound) is performed by the connect verb, not here.
func LocalPortBase(name string) int {
	h := sha256.Sum256([]byte("quic-link-v1:" + name))
	slot := binary.BigEndian.Uint16(h[0:2]) % 2000
	return 42000 + 10*int(slot)
}

// LocalPorts resolves the ssh and docker local TCP ports for a server, honouring
// any per-service overrides in the override map. A zero or absent entry means
// "auto": ssh defaults to base, docker defaults to base+1.
func LocalPorts(name string, override map[string]int) (ssh, docker int) {
	base := LocalPortBase(name)
	ssh = base
	docker = base + 1
	if override != nil {
		if v, ok := override["ssh"]; ok && v != 0 {
			ssh = v
		}
		if v, ok := override["docker"]; ok && v != 0 {
			docker = v
		}
	}
	return ssh, docker
}
