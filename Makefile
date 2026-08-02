.PHONY: build
build:
	goreleaser build --snapshot --single-target --clean -o external-dns-netcup-webhook

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: test
test:
	go test ./...

.PHONY: generate
generate:
	embedmd -w `find . -path ./vendor -prune -o -name "*.md" -print`
