SHELL := /usr/bin/env bash

# The name of the executable (default is current directory name)
TARGET := $(shell echo $${PWD##*/})

# go source files, ignore vendor directory
SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

COMMIT := $(shell git rev-parse --short HEAD)
TODAY := $(shell date +%Y-%m-%d)
LDFLAGS=-ldflags "-X main.COMMIT=${COMMIT} -X main.DATE=${TODAY}"

# looks like abuse
.PHONY: all build obsdbuild clean fmt simplify test testcov testcovweb

all: fmt build test lint

build:
	CGO_ENABLED=0 go build ${LDFLAGS}

obsdbuild:
	CGO_ENABLED=0 GOOS=openbsd GOARCH=amd64 go build ${LDFLAGS} -o ${TARGET}.obsd

clean:
	rm -f ${TARGET}
	rm -f ${TARGET}.obsd
	rm -f coverage.out

fmt:
	gofmt -l -w ${SRC}

simplify:
	gofmt -s -l -w ${SRC}

test:
	go vet
	go test -v

testcov:
	go test -cover -v

testcovweb:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out
	rm -f coverage.out

lint: staticcheck shadow

ensure-shadow-installed:
	@command -v shadow > /dev/null || go install golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow@latest
shadow: ensure-shadow-installed
	shadow ./...

ensure-staticcheck-installed:
	@command -v staticcheck > /dev/null || go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck: ensure-staticcheck-installed
	staticcheck ./...

update-deps:
	go get -u -t ./...
