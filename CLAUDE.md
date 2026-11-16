# CLAUDE.md — vgi-cve

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion. This worker is
modeled on [`vgi-grpc`](https://github.com/Query-farm/vgi-grpc), the reference
Go VGI worker — same tooling, layout, and SDK conventions.

## What this is

A [VGI](https://query.farm) worker (Go) that looks up **CVE/vulnerability data**
from the **NVD 2.0 API**, adds prioritization signals from **CISA KEV** (known
exploited) and **FIRST EPSS** (exploit probability), queries **OSV.dev** for
open-source package advisories, and computes **CVSS v3.1 scores**, exposed as
DuckDB SQL functions. Defensive vuln-management tool. Built on the
[`vgi-go`](https://github.com/Query-farm/vgi-go) SDK over stdio. Catalog name:
`cve`.

## Layout

```
cmd/vgi-cve-worker/main.go    stdio entry point; assembles the worker + catalog
cmd/mockserver/main.go        standalone mock NVD HTTP server for the SQL E2E
internal/cveworker/
  cvss.go                     offline CVSS math: Severity() + BaseScore() (v3.1 equation)
  client.go                   NVD 2.0 HTTP client (net/http + encoding/json); CVERow projection
  functions.go                the 2 scalars + 3 NVD table functions + bands table + Register(w)
  kev.go                      CISA KEV feed client (15-min in-process cache) + kev() / kev_cve()
  epss.go                     FIRST EPSS client (2000-char cve= chunking, offset paging) + epss(list)
  osv.go                      OSV.dev client (/query paging, /vulns/{id}) + osv_query() / osv_vuln()
  httpget.go                  shared doJSON (status→error mapping, errNotFound) + generic nextRows cursor
  arrays.go                   nullable VARCHAR / DATE and VARCHAR[] column builders
  examples.go                 composed examples (incl. NVD+KEV+EPSS prioritization, OSV+KEV)
  *_test.go                   offline CVSS tests + httptest-mock client/function tests
internal/mocknvd/
  server.go                   Handler(): mounts every mock API at its real path; NVD by query param
  data.go                     canned NVD fixtures (Log4Shell, search/CPE records)
  kev.go / epss.go / osv.go   canned KEV feed, EPSS API (2000-char cap, 100-row page cap), OSV API
test/sql/*.test               haybarn-unittest sqllogictest — authoritative E2E
Makefile                      build / test-unit / test-sql / lint
```

## The offline-CVSS vs. API split (read first)

The function surface deliberately splits into two halves:

- **Offline scalars (`cvss_severity`, `cvss_base_score`)** — pure CVSS math in
  `cvss.go`. No network, fully deterministic, trivially unit-testable against
  known vectors. These implement the `vgi.ScalarFunction` interface directly
  (no typed wrapper) and use `vgi.MapColumn(...)` to map the single input column.
- **Table functions (`cve`, `cve_search`, `cpe_cves`)** — live NVD 2.0 API
  lookups in `client.go`, wrapped as `vgi.TypedTableFunc[S]` in `functions.go`.
  Each accepts named `base_url` + `api_key` options; the E2E points `base_url`
  at the mock so it never touches the real NVD.
- **Exploit intel + OSV table functions (`kev`, `kev_cve`, `epss`, `osv_query`,
  `osv_vuln`)** — one file per source. Each takes a `base_url` that replaces the
  whole endpoint: the KEV feed URL, the EPSS endpoint, or the OSV root
  (`.../v1`). `epss` takes a `VARCHAR[]` positional. `vgi.BindArgs` can't
  extract LIST scalars, so `epssArgs` (with the `[]string` field) only feeds
  `DeriveArgSpecs`. `NewState` binds the named options through `epssNamedArgs`
  and reads the list with `stringListArg`. DuckDB rejects subqueries as
  table-function arguments ("Table function cannot contain subqueries"), so a
  dynamic list goes through `SET VARIABLE` + `getvariable()`.

`cvss_base_score` follows the official CVSS v3.1 base equation
(ISCBase → Impact → Exploitability → Roundup), including the Scope:Changed path
(`1.08 *` multiplier, different impact formula, higher PR weights) and the spec's
integer-arithmetic "Roundup" so floating-point drift never bumps a score.

## The Go SDK worker pattern (reusable for future Go workers)

A worker is `main()` assembling a `*vgi.Worker` and registering functions:

```go
w := vgi.NewWorker(vgi.WithCatalogName("cve"), vgi.WithCatalogComment("..."))
cveworker.Register(w)   // RegisterScalar(...) x2 + RegisterTable(...) x3
w.RunStdio()            // or w.RunHttp("127.0.0.1:0") behind a --http flag
```

- **Scalar**: implement `Name/Metadata/ArgumentSpecs/OnBind/Process` (the
  `vgi.ScalarFunction` interface) and pass the struct straight to
  `w.RegisterScalar`. `OnBind` returns `vgi.BindResult(arrowType)`; `Process`
  maps with `vgi.MapColumn(params, batch, 0, builder, fn)`.
- **Table**: a `vgi.TypedTableFunc[S]` wrapped with `vgi.AsTableFunction[S]`.
  Methods: `Name`, `Metadata`, `ArgumentSpecs` (from `vgi.DeriveArgSpecs(args{})`),
  `OnBind` (→ `vgi.BindSchema(schema)`), `NewState` (bind args with
  `vgi.BindArgs`; do the network fetch here, store `Rows`+`Offset`), `Process`
  (emit the next cursor slice with `out.Emit`, advance `Offset`, then
  `out.Finish()` when the cursor is drained — see Sharp edge #1 for why the
  cursor is mandatory for HTTP).

**Argument struct tags** (`vgi.DeriveArgSpecs` / `vgi.BindArgs`):

```go
type cveArgs struct {
    CVEID   string `vgi:"pos=0,doc=CVE identifier"`
    BaseURL string `vgi:"name=base_url,default=,doc=Override the NVD base URL"`
    APIKey  string `vgi:"name=api_key,default=,doc=NVD API key"`
}
```

- `pos=N` → positional. A field **without** `pos` but **with** `default=`
  becomes a **named optional** argument (DuckDB `name := value`). `name=` sets
  the wire name.

Build arrays in `Process` with `vgi.BuildStringArray` / `vgi.BuildFloat64Array`
etc., then `array.NewRecordBatch(schema, []arrow.Array{...}, n)`. For a nullable
column (the NULL `cvss_score`), build a `array.Float64Builder` directly and call
`AppendNull()` per row — see `buildNullableScore`.

## Sharp edges (learned the hard way)

1. **Table-function state is `gob`-encoded by the SDK** between `NewState` and
   `Process` (it may cross a process boundary), and the SDK **panics at
   registration** if state isn't gob-encodable. So state `S` must have
   **exported, gob-encodable fields only** — no `arrow.Record`, no interfaces,
   channels, funcs, or unexported fields. (The exported-field check counts named
   exported fields, so an embedded helper type must itself be **exported** —
   `CursorState`, not `cursorState` — or the worker panics at startup.) The
   pattern every table function here uses: **fetch rows eagerly in `NewState`**,
   store a plain exported Go slice (`Rows []CVERow`) plus an explicit cursor, and
   **rebuild the Arrow batch in `Process`**. `TestRegisterDoesNotPanic` guards
   against regressions.

   **Streaming state MUST carry an explicit cursor, not a bare `Done bool`**
   (the HTTP-continuation invariant). Over the **stateless HTTP transport** the
   worker keeps no live state between `Process` ticks — the framework
   round-trips the producer state through a continuation token (gob-snapshotting
   the user state each tick, emitting ≤1 data batch per response, resuming from
   the token). A `Done` flag flipped *after* the single `Emit` observes the
   pre-`Emit` snapshot on resume, re-emits the same rows forever, and pins the
   worker in an infinite loop (subprocess/unix hold live state in memory, so they
   never hit it). The fix: an exported cursor `Rows []CVERow; Offset int`
   (`CursorState`). `Process` emits a bounded slice from `Offset`, advances
   `Offset` **before** yielding, and `out.Finish()`es when `Offset >= len(Rows)`.
   The framework snapshots `Offset` into the token, so HTTP resumes correctly and
   terminates. `TestCursorSurvivesContinuation` (gob round-trips between ticks)
   guards this.

2. **`haybarn-unittest` silently SKIPS `require vgi`.** Under haybarn the
   extension is not autoloaded for `require`, so a `.test` using `require vgi`
   is skipped (looks green but ran nothing). Use an explicit `statement ok` /
   `LOAD vgi;` instead — every `.test` here does. Tests `require-env
   VGI_CVE_WORKER` and `ATTACH 'cve' AS cve (TYPE vgi, LOCATION
   '${VGI_CVE_WORKER}')`.

3. **No CVSS metrics → NULL, not 0.** A CVE still under analysis has no metrics;
   `CVERow.Score` is a `*float64` so a nil pointer becomes a real SQL NULL.

4. **Bounded + timed network.** Searches page (`resultsPerPage`/`startIndex`)
   but stop at `MaxResults = 100`; the HTTP client has a 30 s timeout. 4xx/5xx,
   429 (rate limit), 404 (unknown CVE), and bad JSON all map to clear errors.
   Other bounds: `MaxOSVResults = 1000`, `MaxEPSSCVEs = 10000`, and EPSS's
   documented 2000-char limit on `cve=` (`chunkCVEParam`). An unknown id is
   zero rows for `osv_vuln` and `kev_cve`, but still an error for NVD `cve()`.

5. **Dates are DATE, timestamps are VARCHAR.** KEV `date_added`/`due_date` and
   EPSS `date` are Arrow date32, so DuckDB sees `DATE`. NVD/OSV timestamps stay
   ISO-8601 `VARCHAR`, matching the original NVD surface.

## Mock-NVD E2E (how `make test-sql` works)

`make test-sql` runs `ci/run-integration.sh` (adapted from the vgi-starter)
once per transport — stdio, launch, http — exactly as CI's matrix does:

1. `make build` compiles `vgi-cve-worker`; `make tools` installs the pinned
   `haybarn-unittest` into `.tools`.
2. The script builds `cmd/mockserver`, starts it on a free port (it prints
   `PORT:<n>`) and exports `VGI_CVE_TEST_URL=http://127.0.0.1:<n>/rest/json/cves/2.0`
   plus `VGI_CVE_KEV_URL` / `VGI_CVE_EPSS_URL` / `VGI_CVE_OSV_URL`; the `.test`
   files pass these as `base_url`.
3. It sets `VGI_CVE_WORKER` (the ATTACH `LOCATION`) per transport: the binary
   path, `launch:<path>`, or `http://127.0.0.1:<port>` of a `--http` worker.
4. It warms the signed `vgi` extension, runs the staged suite with error-skipping
   disabled, and fails on any skip not listed in `EXPECTED_SKIP_REASONS`.

`cmd/mockserver` and the Go tests share `internal/mocknvd.Handler()`, which
serves canned NVD 2.0 JSON keyed on query param: `cveId` (Log4Shell record or
404), `keywordSearch` (3 paginated records), `cpeName` (3 records incl. one with
no CVSS → NULL score, severity and vector).

## Test inventory

- **Go (`make test-unit`)** — `internal/cveworker/cvss_test.go` checks the
  severity bands and `BaseScore` against known vectors (9.8 / 10.0 / 7.5 /
  Scope:Changed) plus malformed-vector errors; `client_test.go` and
  `functions_test.go` run against `httptest` + `internal/mocknvd` and assert the
  `cve` parse, `cve_search` pagination, `cpe_cves` (incl. NULL score), and
  404/500/429/bad-JSON errors, plus the VGI `NewState` path and NULL→no-rows.
- **SQL (`make test-sql`)** — `test/sql/cvss_offline.test` (offline scalars, no
  mock needed), `test/sql/cve_api.test` (NVD table functions via the mock
  `base_url`, incl. an unknown-CVE `statement error`) and
  `test/sql/exploit_intel.test` (KEV/EPSS/OSV: DATE and list types, EPSS
  batching of 400 ids, OSV paging and version filtering, and the composed
  NVD+KEV+EPSS and OSV+KEV queries).
- **Go** also has `exploit_intel_test.go`: KEV parse/cache/errors, EPSS
  dedup/history/batching (asserts no request's `cve=` exceeds 2000 chars),
  OSV paging/ranges/404→nil, and gob round-trips of the new cursor states.

## Conventions

- Source files start with `// Copyright 2026 Query Farm LLC - https://query.farm`.
- `gofmt`, `go vet`, and `go test ./...` must be clean before committing.
- The worker is MIT-licensed; it uses only the Go stdlib for the NVD client and
  CVSS math, plus the vgi-go SDK for the protocol.
```
