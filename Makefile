VERSION ?= dev
ARCH ?= amd64
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS ?= -X vfw/internal/buildinfo.Version=$(VERSION) -X vfw/internal/buildinfo.Commit=$(COMMIT)

.PHONY: build test race deb clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/vfw ./cmd/vfw

test:
	go test ./...

race:
	CGO_ENABLED=1 go test -race ./...

deb:
	bash scripts/build-deb.sh

clean:
	rm -rf dist
