#!/bin/sh
# Copyright 2026 Query Farm LLC - https://query.farm
#
# Dispatch the single vgi-cve image into one of its transports:
#   http   (default) the HTTP server on $PORT (8000), bound 0.0.0.0 so a
#                    published host port and the HEALTHCHECK reach it. The SDK
#                    serves GET /health at the root.
#   stdio            a worker DuckDB spawns over stdio (on-host execution).
#   unix <sock>      the AF_UNIX launcher socket (on-host); the SDK prints
#                    "UNIX:<path>" once listening.
# Any other first argument is exec'd verbatim (escape hatch for debugging).
#
# The worker is stateless (offline CVSS table + live NVD fetches), so there is
# no /data to create and no state env to wire — each mode just exec's the binary.
set -e

case "${1:-http}" in
  http)
    shift 2>/dev/null || true
    # The Go SDK's --http binds exactly the --http-addr it is given (default
    # 127.0.0.1:0, an ephemeral loopback port). In a container we must bind
    # 0.0.0.0 on a FIXED port so `-p $PORT:$PORT` and the HEALTHCHECK reach it.
    exec vgi-cve-worker --http --http-addr "0.0.0.0:${PORT:-8000}" "$@"
    ;;
  stdio)
    shift 2>/dev/null || true
    exec vgi-cve-worker "$@"
    ;;
  unix)
    shift 2>/dev/null || true
    # Remaining args are passed through; the caller supplies the socket path,
    # e.g. `docker run ... IMG unix --unix /sock/cve.sock`.
    exec vgi-cve-worker "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
