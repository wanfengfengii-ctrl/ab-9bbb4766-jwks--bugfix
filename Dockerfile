# syntax=docker/dockerfile:1

# ---- build stage: fully static binaries, no external modules ----
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/calibration-server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/keygen            ./cmd/keygen \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/verify            ./cmd/verify

# ---- runtime image: hardening + HEALTHCHECK for the resource server ----
FROM alpine:3.20 AS server
RUN apk add --no-cache ca-certificates wget \
 && adduser -D -u 65532 cal \
 && mkdir -p /etc/calibration /secrets/issuer /evidence /var/lib/calibration/replay \
 && chown -R cal:cal /var/lib/calibration/replay
COPY --from=build /out/calibration-server /usr/local/bin/calibration-server
USER cal:cal
EXPOSE 8080
# Application-level health check; Compose gates the verify job on this.
HEALTHCHECK --interval=3s --timeout=2s --start-period=10s --retries=30 \
  CMD wget -q -O- http://127.0.0.1:8080/healthz | grep -q '"ok"' || exit 1
ENTRYPOINT ["/usr/local/bin/calibration-server"]

# ---- one-shot acceptance image: toolchain + sources + all binaries ----
# The verify service runs `go test`, `go build`, and live smoke tests, so it
# intentionally keeps the Go toolchain and module sources. Runs as a
# non-root user so the read-only-evidence check is meaningful.
FROM golang:1.23-alpine AS verify
RUN apk add --no-cache ca-certificates wget \
 && adduser -D -u 65532 cal \
 && mkdir -p /etc/calibration /secrets/issuer /evidence \
 && chown -R cal:cal /etc/calibration /secrets/issuer /evidence /home/cal
WORKDIR /app/src
COPY . .
COPY --from=build /out/calibration-server /usr/local/bin/calibration-server
COPY --from=build /out/keygen             /usr/local/bin/keygen
COPY --from=build /out/verify             /usr/local/bin/verify
ENV CONFIG_PATH=/etc/calibration/config.json \
    ISSUER_KEY=/secrets/issuer/jwk-private.json \
    BASE_URL=http://calibration-server:8080 \
    SRC_DIR=/app/src \
    SERVER_BIN=/usr/local/bin/calibration-server \
    GOTOOLCHAIN=local \
    GOPROXY=off \
    GOCACHE=/tmp/go-cache
USER cal:cal
# Acceptance entrypoint; `keygen` is available via `command:` override.
ENTRYPOINT ["/usr/local/bin/verify"]
