FROM golang:1.24.3-alpine3.21 as builder
WORKDIR /app
COPY . /app

RUN apk --no-cache add make git && make build

FROM alpine:3.21

COPY --from=builder /app/external-dns-netcup-webhook /
ENTRYPOINT ["/external-dns-netcup-webhook"]
