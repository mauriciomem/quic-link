package main

// vhost_limit_exit_test.go covers what an operator meets when they configure
// more published names than this build will serve: the exit code their
// supervisor sees, and the sentence they read.
//
// Both were wrong when this was only enforced where the name table is built.
// The count was the one member of the "your configuration is wrong" family that
// exited 1 while unknown keys, unparseable addresses and names that are not
// hostnames all exited 2, and the sentence carried the same word twice.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/router"
)

// tooManyVhosts builds a published-name table one entry larger than this build
// will serve. Every key is a legal hostname and every address parses, so the
// count is the only thing wrong with it.
func tooManyVhosts() map[string]string {
	hosts := make(map[string]string, router.MaxVhosts+1)
	for i := 0; i < router.MaxVhosts+1; i++ {
		hosts[fmt.Sprintf("svc%d.server1.internal", i)] = "tcp://127.0.0.1:3000"
	}
	return hosts
}

// TestAgentTooManyVhosts_ExitsTwo is the defect this file exists for.
//
// An operator who writes too many published names has made the same kind of
// mistake as one who writes a name that is not a hostname, and a wrapper script
// that treats exit 2 as "the configuration needs editing" must reach the same
// conclusion for both. Exiting 1 puts this one in with crashes and network
// failures, which is where an operator stops looking at their own file.
//
// It is driven through the real command line rather than through the exit-code
// mapping on its own, because the mapping was never the part that was wrong:
// the error simply never carried the marking the mapping looks for.
func TestAgentTooManyVhosts_ExitsTwo(t *testing.T) {
	unsetQLEnvForTest(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// A real key, named by the configuration, deliberately. Without one the
	// agent stops at the missing key before it ever builds its name table, so
	// this test would still fail if the count check were taken out — but it
	// would be failing about a key, and would say so whatever the count check
	// did. With the key present the only thing left between the configuration
	// and a running agent is the count.
	keyPath := filepath.Join(tmp, "key.pem")
	if err := runKeygen([]string{"--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "schema = 1\n[identity]\nkey_file = %q\n[agent]\nlisten = \"127.0.0.1:0\"\nauthorized_clients = [%q]\n",
		keyPath, mustTestPin(t))
	b.WriteString("[agent.vhosts]\n")
	for host, addr := range tooManyVhosts() {
		fmt.Fprintf(&b, "%q = %q\n", host, addr)
	}
	path := writeTestConfig(t, b.String())

	err := runVerb([]string{"--config", path, "agent"})
	if err == nil {
		t.Fatalf("an agent configured with %d published names started", router.MaxVhosts+1)
	}
	if got := exitCode(err); got != 2 {
		t.Errorf("exitCode = %d, want 2 — every other bad agent configuration exits 2, "+
			"and a supervisor branching on that will misread this one: %v", got, err)
	}
	for _, want := range []string{strconv.Itoa(router.MaxVhosts + 1), strconv.Itoa(router.MaxVhosts)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator cannot tell how far "+
				"over they are: %q", want, err.Error())
		}
	}
}

// TestAgentTooManyVhosts_MessageIsNotPrefixedTwice guards the sentence itself.
//
// This is the first thing an operator sees when their agent will not start, and
// it used to read "router: router: ..." because the verb added a label the
// refusal already began with. Two tests are needed, not one: the check above
// never reaches the name table now that the configuration is validated first,
// so it cannot see the string this one is about.
//
// agentRun is called directly on purpose. That is the path a set of names would
// take if it reached the name table without passing the configuration
// validator, and it is the only way to read the sentence that path produces.
func TestAgentTooManyVhosts_MessageIsNotPrefixedTwice(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	unsetQLEnvForTest(t)

	keyPath := filepath.Join(tmp, "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := runKeygen([]string{"--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	ag := config.Agent{Listen: "127.0.0.1:0", Vhosts: tooManyVhosts()}
	err := agentRun(context.Background(), ag, keyPath, pinList{mustTestPin(t)}, minimalIdentityCfg())
	if err == nil {
		t.Fatalf("the name table accepted %d names", router.MaxVhosts+1)
	}
	if strings.Contains(err.Error(), "router: router:") {
		t.Errorf("the operator is told the same word twice: %q", err.Error())
	}
}
