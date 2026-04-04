APP_NAME := intelligence-api
BUILD_DIR := bin
VERSION := $(shell git describe --tags --always --dirty)

.PHONY: all build clean deps test test-integration test-all run release deploy docker-reset

all: test build

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME) ./cmd/api/

clean:
	rm -rf $(BUILD_DIR)

deps:
	go get -u ./...
	go mod tidy

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
