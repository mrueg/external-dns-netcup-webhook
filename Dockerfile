FROM golang:1.21 as builder

WORKDIR /app

COPY . /app

RUN make build

FROM alpine:3.18.0

COPY --from=builder /app/external-dns-netcup-webhook /

ENTRYPOINT ["/external-dns-netcup-webhook"]
