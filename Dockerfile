FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o sigstore-certificate-maker

FROM alpine:latest
COPY --from=builder /app/sigstore-certificate-maker /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/sigstore-certificate-maker"]