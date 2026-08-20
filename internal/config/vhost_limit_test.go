package config_test

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/router"
)

// agentConfigWithVhosts writes a valid agent configuration carrying n
// published names, and returns its path.
//
// Every name is a legal hostname and every address parses, so the only thing
// that can be wrong with the file is how many names are in it. A test that
// built a name the validator would reject anyway could not tell the count
// check from the name check.
func agentConfigWithVhosts(t *testing.T, n int) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "schema = 1\n[agent]\nlisten = \"127.0.0.1:0\"\nauthorized_clients = [%q]\n",
		mustPin(t))
	b.WriteString("[agent.vhosts]\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\"svc%d.server1.internal\" = \"tcp://127.0.0.1:3000\"\n", i)
	}
	return writeConfig(t, b.String())
}

// TestAgentVhosts_TooManyIsAConfigurationError is about which kind of mistake
// this is, not about whether it is caught.
//
// Every other way of getting the published-name table wrong — an unknown key, a
// name that is not a hostname, an address that does not parse — is reported as
// a configuration error, and an operator's supervisor unit or wrapper script is
// entitled to branch on that. A count that was only ever checked when the table
// was built would be the one member of that set reported as something else, so
// the script would treat "your file is too big" as an unexplained crash.
//
// Both numbers have to be in the message. Being told the file is too large
// without being told by how much leaves the operator to count the entries
// themselves, and being told the limit without their own count leaves them
// unable to tell a file that is one over from one that is double.
func TestAgentVhosts_TooManyIsAConfigurationError(t *testing.T) {
	unsetAllQLEnv(t)
	path := agentConfigWithVhosts(t, router.MaxVhosts+1)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleAgent)
	if err == nil {
		t.Fatalf("a configuration of %d published names was accepted", router.MaxVhosts+1)
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("the refusal is not a configuration error, so it will not exit 2: %v", err)
	}
	for _, want := range []string{strconv.Itoa(router.MaxVhosts + 1), strconv.Itoa(router.MaxVhosts)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator cannot tell how far over "+
				"they are: %q", want, err.Error())
		}
	}
}

// TestAgentVhosts_TheLimitItselfLoads is the control for the test above.
//
// A check written with the comparison the wrong way round would refuse the
// boundary too, and the number the message names would then be one no operator
// could actually use. Nothing else here would notice.
func TestAgentVhosts_TheLimitItselfLoads(t *testing.T) {
	unsetAllQLEnv(t)
	path := agentConfigWithVhosts(t, router.MaxVhosts)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.Validate(config.RoleAgent); err != nil {
		t.Fatalf("a configuration of exactly %d published names was refused: %v",
			router.MaxVhosts, err)
	}
	if got := len(cfg.Agent.Vhosts); got != router.MaxVhosts {
		t.Errorf("the loaded configuration holds %d published names, want %d",
			got, router.MaxVhosts)
	}
}
