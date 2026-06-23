# vgi-cve Makefile
#
# A VGI worker (Go) that looks up CVE/vulnerability data from the NVD 2.0 API
# and computes CVSS scores as DuckDB SQL functions. Targets:
#
#   make build       Build the worker + mock-server binaries
#   make test-unit   Run the pure-Go unit tests (offline CVSS + httptest mock)
#   make test-sql    Run the haybarn-unittest SQL E2E against a local mock NVD
#   make test        test-unit + test-sql
#   make fmt         gofmt -w
#   make vet         go vet
#   make lint        golangci-lint (if installed) else vet
#   make clean       Remove built binaries
#
# test-sql needs haybarn-unittest on PATH:
#   uv tool install haybarn-unittest
#   export PATH="$$HOME/.local/bin:$$PATH"

WORKER_BIN  := vgi-cve-worker
MOCK_BIN    := mockserver
WORKER_CMD  := ./cmd/vgi-cve-worker
MOCK_CMD    := ./cmd/mockserver

TEST_DIR     := .
TEST_PATTERN := test/sql/*

# Absolute path to the built worker (the VGI extension launches it via LOCATION).
WORKER_PATH := $(CURDIR)/$(WORKER_BIN)
MOCK_PATH   := $(CURDIR)/$(MOCK_BIN)

.PHONY: build test test-unit test-sql fmt vet lint clean

build:
	go build -o $(WORKER_BIN) $(WORKER_CMD)
	go build -o $(MOCK_BIN) $(MOCK_CMD)

test: test-unit test-sql

test-unit:
	go test ./...

# Build both binaries, start the mock NVD server on a free port (it prints
# PORT:<n>), point the worker's table functions at it via VGI_CVE_TEST_URL
# (used as the base_url option), run the SQL suite, then stop the mock server.
# We capture haybarn's exit status so the trap's SIGTERM to the mock does not
# mask a successful test run.
test-sql: build
	@set -e; \
	TMP_PORT_FILE=$$(mktemp); \
	$(MOCK_PATH) --addr 127.0.0.1:0 >$$TMP_PORT_FILE 2>/dev/null & \
	MOCK_PID=$$!; \
	trap 'kill $$MOCK_PID 2>/dev/null; wait $$MOCK_PID 2>/dev/null; rm -f $$TMP_PORT_FILE' EXIT; \
	PORT=""; \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
		PORT=$$(sed -n 's/^PORT:\([0-9][0-9]*\)$$/\1/p' $$TMP_PORT_FILE 2>/dev/null | head -1); \
		[ -n "$$PORT" ] && break; \
		sleep 0.2; \
	done; \
	if [ -z "$$PORT" ]; then echo "ERROR: mock server did not report a port" >&2; exit 1; fi; \
	echo "mock NVD server listening on 127.0.0.1:$$PORT (pid $$MOCK_PID)"; \
	STATUS=0; \
	VGI_CVE_WORKER="$(WORKER_PATH)" \
	VGI_CVE_TEST_URL="http://127.0.0.1:$$PORT/rest/json/cves/2.0" \
		haybarn-unittest --test-dir "$(TEST_DIR)" "$(TEST_PATTERN)" || STATUS=$$?; \
	exit $$STATUS

fmt:
	gofmt -w .

vet:
	go vet ./...

lint:
	golangci-lint run

clean:
	rm -f $(WORKER_BIN) $(MOCK_BIN)
