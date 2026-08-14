APP_NAME := intelligence-api
CLI_NAME := sactl
BUILD_DIR := bin
VERSION := $(shell git describe --tags --always --dirty)

.PHONY: all build build-cli install-cli clean deps lint lint-new test test-integration test-all run release deploy docker-reset

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
