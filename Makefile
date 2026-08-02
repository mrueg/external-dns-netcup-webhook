.PHONY: build
build:
	go build -o external-dns-netcup-webhook .

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: test
test:
	go test ./...

.PHONY: generate
generate:
	embedmd -w `find . -path ./vendor -prune -o -name "*.md" -print`
