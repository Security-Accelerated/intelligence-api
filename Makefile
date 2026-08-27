APP_NAME := intelligence-api
CLI_NAME := sactl
BUILD_DIR := bin
VERSION := $(shell git describe --tags --always --dirty)

.PHONY: all build build-cli install-cli clean deps lint lint-new verify test test-integration test-all run release deploy docker-reset

all: test build build-cli

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME) ./cmd/api/

# The operator CLI. Built into bin/ alongside the server.
build-cli:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(CLI_NAME) ./cmd/sactl/

# Installs sactl onto PATH (GOBIN, or GOPATH/bin), so it can be run from the
# directory holding .env rather than from the repo.
install-cli:
	go install -ldflags "-X main.version=$(VERSION)" ./cmd/sactl/
	@echo "installed $(CLI_NAME) $(VERSION) to $$(go env GOBIN 2>/dev/null || echo $$(go env GOPATH)/bin)"

clean:
	rm -rf $(BUILD_DIR)

deps:
	go get -u ./...
	go mod tidy

# golangci-lint defaults to reporting at most 50 issues per linter and 3 per
# identical message, silently. Both targets turn that off: a capped count reads
# as a backlog you can finish and then cannot, and on lint-new it would hide
# findings in the very code under review.
LINT_FLAGS := --timeout 10m --max-issues-per-linter=0 --max-same-issues=0

# Full lint over the whole tree. Config lives in .golangci.yml, copied from the
# fleet repo — edit it there and re-run bin/lint-apply.sh rather than diverging.
lint:
	golangci-lint run $(LINT_FLAGS) ./...

# Only findings introduced relative to main. This is what CI gates on, so the
# pre-existing backlog does not block unrelated work.
lint-new:
	golangci-lint run $(LINT_FLAGS) --new-from-rev=origin/main ./...

# The one command that answers "did it work?". Every repo in the fleet has a
# `verify` target with the same three properties, whatever the language, so
# nobody — human or agent — has to work out the incantation for this repo:
#
#   1. Non-destructive. No containers, no volumes, no network mutation, and no
#      writes to tracked files. Safe on a cold clone and safe in CI.
#   2. Exits non-zero on any failure.
#   3. Runs everything before reporting, so one run shows every problem rather
#      than the first one.
#
# Deliberately does NOT run `go mod tidy` the way `test` does. A target that
# rewrites go.mod while claiming to verify can turn a passing run into a dirty
# tree, which is a rude surprise in CI and a confusing one locally.
#
# Uses `lint-new`, not `lint`: the tree carries a known backlog of pre-existing
# findings, and a gate that fails the day it lands is a gate people learn to
# skip. This matches what CI actually enforces.
verify:
	@failed=0; \
	printf '\033[2m→ gofmt\033[0m\n'; \
	unformatted="$$(gofmt -l . | grep -v '^vendor/' || true)"; \
	if [ -n "$$unformatted" ]; then \
		printf '\033[31m✗ needs gofmt:\033[0m\n%s\n' "$$unformatted"; failed=1; \
	fi; \
	printf '\033[2m→ go vet\033[0m\n'; \
	go vet ./... || failed=1; \
	printf '\033[2m→ golangci-lint (new findings vs main)\033[0m\n'; \
	golangci-lint run $(LINT_FLAGS) --new-from-rev=origin/main ./... || failed=1; \
	printf '\033[2m→ go test -race\033[0m\n'; \
	go test -race -count=1 ./... || failed=1; \
	printf '\033[2m→ integration\033[0m\n'; \
	go test -race -count=1 -tags=integration . || failed=1; \
	echo ""; \
	if [ $$failed -eq 0 ]; then \
		printf "\033[32m✓ verify passed\033[0m\n"; \
	else \
		printf "\033[31m✗ verify failed\033[0m\n"; \
		exit 1; \
	fi

test:
	go mod tidy
	go test -race -count=1 ./...

test-integration:
	go mod tidy
	go test -race -count=1 -tags=integration -v .

test-all:
	@failed=0; \
	$(MAKE) test || failed=1; \
	$(MAKE) test-integration || failed=1; \
	echo ""; \
	if [ $$failed -eq 0 ]; then \
		printf "\033[32m✓ All tests passed.\033[0m\n"; \
	else \
		printf "\033[31m✗ Some tests failed.\033[0m\n"; \
		exit 1; \
	fi

run: build
	./$(BUILD_DIR)/$(APP_NAME)

release:
	@test -n "$(V)" || (echo "usage: make release V=v0.1.0" && exit 1)
	git tag -a $(V) -m "Release $(V)"
	git push origin $(V)

deploy:
	fly deploy --build-arg VERSION=$(VERSION)

docker-reset:
	./scripts/docker-reset.sh
