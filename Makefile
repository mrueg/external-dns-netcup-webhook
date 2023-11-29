VERSION := $(shell cat VERSION)
GIT_COMMIT := $(shell git rev-parse HEAD)
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
PROJECT := external-dns-netcup-webhook 
PKG := github.com/prometheus/common

.PHONY: build
build:
	go build -ldflags "-s -w -X ${PKG}/version.Version=${VERSION} -X ${PKG}/version.Revision=${GIT_COMMIT} -X ${PKG}/version.Branch=${BRANCH} -X ${PKG}/version.BuildUser=${USER}@${HOST} -X ${PKG}/version.BuildDate=${BUILD_DATE}" -o ${PROJECT} .

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: test
test:
	go test ./...

.PHONY: generate
generate:
	embedmd -w `find . -path ./vendor -prune -o -name "*.md" -print`
