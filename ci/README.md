# CI: the vgi-cve worker integration suite

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs the Go unit
tests and this repo's sqllogictest suite (`test/sql/*.test`) against the worker
through the **real DuckDB `vgi` extension** on every push / PR. The harness,
[`run-integration.sh`](run-integration.sh), is adapted from the vgi-starter's
and is what `make test-sql` runs locally too.

## Transport matrix

The same suite runs once per transport (`SQL E2E (stdio|launch|http)`), chosen
by `TRANSPORT`, which changes what `VGI_CVE_WORKER` (the ATTACH `LOCATION`) is:

| `TRANSPORT` | Worker                                              | `VGI_CVE_WORKER`            |
| ----------- | --------------------------------------------------- | ------------------ |
| `stdio`     | DuckDB spawns the binary over stdin/stdout          | `/abs/path/worker` |
| `launch`    | DuckDB starts it once on an AF_UNIX socket and pools connections | `launch:/abs/path/worker` |
| `http`      | the script starts `worker --http` (prints `PORT:<n>`) | `http://127.0.0.1:<n>` |

For `http` the script also loads `httpfs` after `LOAD vgi;` in the staged
copies: the extension sends worker RPCs through DuckDB's HTTP client, which only
exists once `httpfs` is loaded.

## Backend

The script builds `cmd/mockserver` (canned NVD 2.0, CISA KEV, FIRST EPSS and
OSV.dev JSON at their real paths), starts it on a free port and exports
`VGI_CVE_TEST_URL` / `VGI_CVE_KEV_URL` / `VGI_CVE_EPSS_URL` / `VGI_CVE_OSV_URL`,
which the `.test` files pass as `base_url`. The offline CVSS scalars need no server.

## How it works (no C++ build)

1. `go build` the worker; install the pinned `haybarn-unittest` (the
   DuckDB/Haybarn sqllogictest runner, `HAYBARN_VERSION`) with uv.
2. Stage `test/sql/*.test`, rewriting any `require vgi` / `require <core ext>`
   into explicit `LOAD`s (the standalone runner links no extensions).
3. Warm the extension cache once: `FORCE INSTALL vgi FROM community` plus
   httpfs / json / parquet from core.
4. Run the staged suite in one `haybarn-unittest` invocation.

### Silent-skip guard (no fake passes)

The runner **skips** (exit 0) any test whose error mentions `HTTP`, and exits 0
when no test matched. The script passes a `--test-config` that disables
error-skipping, fails when no test matched, and fails on any skip reason not
listed in `EXPECTED_SKIP_REASONS` (or when fewer than `MIN_EXECUTED` files ran).

The Docker image test (`docker-publish.yml`) reuses the script against the
built image: `WORKER="docker run -i --rm IMG stdio"` for stdio, an
`http://localhost:<port>` URL of a running container for http, with
`SKIP_MOCK=1` and a narrowed `TEST_PATTERN`.

## Streaming table functions over HTTP (the cursor pattern)

The `cve` / `cve_search` / `cpe_cves` table functions stream their result across
multiple `Process` exchanges. Over the **stateless** HTTP transport the worker
holds no live state between ticks — the framework round-trips the producer state
through an opaque continuation token (gob-encoding the user state after each
tick, emitting at most one data batch per response, then resuming from the
token). The position therefore **must live in the serialized state**: a bare
post-`Emit` `Done bool` observes the pre-`Emit` snapshot on resume, re-emits the
same rows forever, and pins the worker in an infinite loop (subprocess/unix keep
the live state in memory, so they were unaffected and hid the bug).

The fix is an explicit gob-encodable **cursor** in the state — `Rows []CVERow;
Offset int` (`CursorState` in `internal/cveworker/functions.go`). `Process`
emits a bounded slice starting at `Offset`, advances `Offset` **before**
yielding, and calls `out.Finish()` once `Offset >= len(Rows)`. Because the
framework snapshots `Offset` into each continuation token, HTTP resumes from the
right row and terminates. `TestCursorSurvivesContinuation` guards this by
gob-round-tripping the state between every simulated tick. This is the reference
pattern for every streaming Go table function that must work over HTTP.

## Run it locally

```bash
make test-sql                   # stdio, launch and http
make test-sql TRANSPORTS=http   # one transport
```
