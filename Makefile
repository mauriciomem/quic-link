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

.PHONY: default build test test-race lint vuln cross clean

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

cross:
	./scripts/cross.sh

clean:
	go clean -cache -testcache
