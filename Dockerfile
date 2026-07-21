# Copyright 2026 Query Farm LLC - https://query.farm
#
# Single image that serves every transport of the `vgi-cve` VGI worker:
#   docker run ... IMG            -> HTTP server on $PORT       (default; Fly.io / local)
#   docker run -i ... IMG stdio   -> stdio worker DuckDB spawns on-host
#   docker run ... IMG unix <sock>-> AF_UNIX launcher socket    (on-host)
# See docker-entrypoint.sh.
#
# This worker is STATELESS: the offline CVSS math is compiled into the binary and
# the live NVD 2.0 lookups are fetched on demand (no on-disk cache, no model
# registry), so there is no /data volume and no `farm.query.vgi.volumes` label.
# The image is just the binary + ca-certificates (for the NVD HTTPS calls) + a
# tiny entrypoint.
# syntax=docker/dockerfile:1

# ---- build stage -----------------------------------------------------------
# CGO is required (CGO_ENABLED=1): the vgi-go SDK links DuckDB via
# duckdb/duckdb-go, so the build needs a C/C++ toolchain and the per-arch DuckDB
# static lib (which a CGO_ENABLED=0 build excludes). Each arch is built on its
# own NATIVE runner in CI, so this compiles without cross-compilation.
FROM golang:1.26-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=1 GOFLAGS=-trimpath

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Resolve modules first (cached as its own layer, keyed on go.mod/go.sum) so a
# code-only change does not re-download the module graph. The registry + build
# caches are BuildKit cache mounts, so the binary is copied OUT to a non-cache
# path before the layer ends (cache mounts do not persist in the image).
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w" -o /worker ./cmd/vgi-cve-worker

# ---- runtime stage ---------------------------------------------------------
# debian-slim (not distroless) so the HEALTHCHECK has a real `curl`. The live
# NVD 2.0 lookups fetch over HTTPS, so ca-certificates is required at runtime.
FROM debian:bookworm-slim

# Build metadata, wired from docker/metadata-action outputs in CI.
ARG VERSION=0.0.0
ARG GIT_COMMIT=unknown
ARG SOURCE_URL=https://github.com/Query-farm/vgi-cve

# Standard OCI labels + the VGI transport-advertisement label. `transports`
# lists the NETWORK transports this image serves (http); stdio and the unix
# launcher socket are on-host spawn modes, not network transports.
LABEL org.opencontainers.image.title="vgi-cve" \
      org.opencontainers.image.description="CVE / vulnerability lookup (NVD 2.0) and offline CVSS v3.1 scoring as a VGI worker for DuckDB/SQL (stdio + HTTP + unix)" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.licenses="MIT" \
      farm.query.vgi.transports='["http"]'

ENV PORT=8000 \
    # Build provenance only; the version the worker advertises over VGI comes
    # from the compiled binary, not this.
    VGI_CVE_GIT_COMMIT=${GIT_COMMIT}

WORKDIR /app

# ca-certificates: the live table functions call the NVD 2.0 API over HTTPS.
# curl: backs the HEALTHCHECK below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# `--chmod` sets the mode in the COPY layer itself (a separate `RUN chmod` would
# rewrite the whole binary into a second layer).
COPY --from=build --chmod=0755 /worker /usr/local/bin/vgi-cve-worker
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Run unprivileged. No state, no volume — there is nothing to own or persist.
RUN useradd --create-home --uid 10001 app
USER app

EXPOSE 8000

# Readiness probe for HTTP mode. Inert for a short-lived stdio container, which
# has no HTTP server (the probe just fails harmlessly there).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT:-8000}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["http"]
