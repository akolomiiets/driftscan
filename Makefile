VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test integration
build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o driftscan ./cmd/driftscan

test:
	go vet ./...
	go test -race ./...

integration:
	go test -tags integration -run Integration -v ./...
