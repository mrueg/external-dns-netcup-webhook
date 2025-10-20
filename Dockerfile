FROM golang:1.25.3-alpine3.22 AS builder
WORKDIR /app
COPY . /app

RUN apk --no-cache add make git && make build

FROM alpine:3.22

COPY --from=builder /app/external-dns-netcup-webhook /
ENTRYPOINT ["/external-dns-netcup-webhook"]
