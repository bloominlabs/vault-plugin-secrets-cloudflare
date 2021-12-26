VERSION 0.6
FROM golang:1.16
WORKDIR /vault-plugin-secrets-cloudflare

deps:
    COPY go.mod go.sum ./
    RUN go mod download
    SAVE ARTIFACT go.mod AS LOCAL go.mod
    SAVE ARTIFACT go.sum AS LOCAL go.sum

build:
    FROM +deps
    COPY *.go .
    COPY --dir ./cmd .
    RUN CGO_ENABLED=0 go build -o bin/vault-plugin-secrets-cloudflare cmd/cloudflare/main.go
    SAVE ARTIFACT bin/vault-plugin-secrets-cloudflare /cloudflare AS LOCAL bin/vault-plugin-secrets-cloudflare

test:
    FROM +deps
    COPY *.go .
    RUN --secret TEST_CLOUDFLARE_TOKEN CGO_ENABLED=0 go test github.com/bloominlabs/vault-plugin-secrets-cloudflare

dev:
  BUILD +build
  LOCALLY
  RUN bash ./scripts/dev.sh

all:
  BUILD +build
  BUILD +test
