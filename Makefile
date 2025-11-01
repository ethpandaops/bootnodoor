# bootoor
BUILDTIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
VERSION := $(shell git rev-parse --short HEAD)

GOLDFLAGS += -X 'github.com/pk910/bootoor/buildver.BuildVersion="$(VERSION)"'
GOLDFLAGS += -X 'github.com/pk910/bootoor/buildver.Buildtime="$(BUILDTIME)"'
GOLDFLAGS += -X 'github.com/pk910/bootoor/buildver.BuildRelease="$(RELEASE)"'

.PHONY: all test coverage clean lint fmt check dev-build

all: build

test:
	go test ./...

coverage:
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -html=coverage.txt -o coverage.html

build:
	@echo version: $(VERSION)
	env CGO_ENABLED=1 go build -v -o bin/ -ldflags="-s -w $(GOLDFLAGS)" ./cmd/*

dev-build:
	@echo version: $(VERSION) [DEBUG BUILD]
	env CGO_ENABLED=1 go build -v -o bin/ -tags debug -ldflags="$(GOLDFLAGS)" ./cmd/*

clean:
	rm -f bin/*
	rm -f coverage.txt coverage.html

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...

check: fmt lint test
