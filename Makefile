APP_NAME := intelligence-api
BUILD_DIR := bin
VERSION := $(shell git describe --tags --always --dirty)

.PHONY: all build clean deps test test-integration run release deploy docker-reset

all: test build

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME) ./cmd/api/

clean:
	rm -rf $(BUILD_DIR)

deps:
	go get -u ./...
	go mod tidy

test: deps
	go test -race -count=1 ./...

test-integration: deps
	go test -race -count=1 -tags=integration -v .

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
