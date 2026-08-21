# A dispatcher, not a build system.
#
# Every target here forwards to a script in scripts/, which is where the real
# work lives. Two reasons for that split, both learned rather than assumed:
#
# The macOS runners CI uses ship GNU Make 3.81 from 2006, because Apple will not
# distribute GPLv3. Anything written here has to avoid a decade and a half of
# make features, and a rule that works on a developer's machine can fail on a
# runner for reasons that have nothing to do with this project.
#
# CodeQL's Go analysis runs bare `make` as its build step, before anything else
# it tries. That makes the default goal part of a security scan's behaviour, so
# it stays a plain build and nothing more.
#
# Requires nothing beyond make and a POSIX shell. Every recipe is a single line.

.PHONY: default build test test-race lint vuln licences proto bench bench-check cross release clean

default: build

build:
	go build ./...

# The suite, plus the reported-result counts. This is what CI runs.
test:
	./scripts/test.sh

test-race:
	./scripts/test.sh --race

# Needs golangci-lint on PATH; see CONTRIBUTING.md.
lint:
	golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./...

# Needs govulncheck on PATH. Text output is deliberate: the JSON mode exits 0
# even when it finds something.
vuln:
	govulncheck ./...

# Every module compiled into the binary is named in THIRD-PARTY-NOTICES.md at the
# version being built.
licences:
	./scripts/licences.sh

# Needs buf on PATH. Style rules first, then the one that matters: whether the
# wire protocol stayed compatible with the default branch.
proto:
	./scripts/proto.sh

# Measure. Pass a count to average over more runs: make bench COUNT=20
bench:
	./scripts/bench.sh $(COUNT)

# Only prove the benchmarks still compile and run. This is what CI does, because
# timings on a shared runner are too noisy to gate on.
bench-check:
	./scripts/bench.sh --check

cross:
	./scripts/cross.sh

# Build the release artifacts locally, exactly as CI does, and verify they are
# reproducible: make release VERSION=v0.1.0
release:
	./scripts/release.sh $(VERSION) --check

clean:
	go clean -cache -testcache
	rm -rf dist
