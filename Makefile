APP_NAME := intelligence-api
BUILD_DIR := bin
VERSION := $(shell git describe --tags --always --dirty)

.PHONY: build clean test run release

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME) ./cmd/api/

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

run: build
	./$(BUILD_DIR)/$(APP_NAME)

release:
	@test -n "$(V)" || (echo "usage: make release V=v0.1.0" && exit 1)
	git tag -a $(V) -m "Release $(V)"
	git push origin $(V)
