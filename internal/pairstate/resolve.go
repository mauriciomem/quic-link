package pairstate

import (
	"errors"

	"github.com/mauriciomem/quic-link/internal/config"
)

var ErrPinConflict = errors.New("pairstate: server pin differs between config and paired.toml")

func EffectiveAuthorized(cfgList, flagList []string, fileEntries []Entry) map[string]struct{} {
	return map[string]struct{}{}
}

func ResolveServers(cfg map[string]config.Server, paired map[string]PairedServer) (map[string]config.Server, error) {
	return nil, errNotImplemented
}
