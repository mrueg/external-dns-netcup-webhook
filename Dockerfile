FROM golang:1.21 as builder

WORKDIR /app

COPY . /app

RUN make build

FROM scratch

COPY --from=builder /app/external-dns-netcup-webhook /

ENTRYPOINT ["/external-dns-netcup-webhook"]

