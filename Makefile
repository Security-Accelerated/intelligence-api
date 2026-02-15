APP_NAME := intelligence-api
BUILD_DIR := bin
VERSION := $(shell git describe --tags --always --dirty)

.PHONY: all build clean test test-integration run release

all: test build

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME) ./cmd/api/

clean:
	rm -rf $(BUILD_DIR)

test:
	go test -race -count=1 ./...

test-integration:
	go test -race -count=1 -tags=integration -v .

run: build
	./$(BUILD_DIR)/$(APP_NAME)

release:
	@test -n "$(V)" || (echo "usage: make release V=v0.1.0" && exit 1)
	git tag -a $(V) -m "Release $(V)"
	git push origin $(V)
