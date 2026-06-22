# CLAUDE.md — vgi-cve

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion. This worker is
modeled on [`vgi-grpc`](https://github.com/Query-farm/vgi-grpc), the reference
Go VGI worker — same tooling, layout, and SDK conventions.

## What this is

A [VGI](https://query.farm) worker (Go) that looks up **CVE/vulnerability data**
from the **NVD 2.0 API** and computes **CVSS v3.1 scores**, exposed as DuckDB
SQL functions. Defensive vuln-management tool. Built on the
[`vgi-go`](https://github.com/Query-farm/vgi-go) SDK over stdio. Catalog name:
`cve`.

## Layout

```
cmd/vgi-cve-worker/main.go    stdio entry point; assembles the worker + catalog
cmd/mockserver/main.go        standalone mock NVD HTTP server for the SQL E2E
internal/cveworker/
  cvss.go                     offline CVSS math: Severity() + BaseScore() (v3.1 equation)
  client.go                   NVD 2.0 HTTP client (net/http + encoding/json); CVERow projection
  functions.go                the 2 scalars + 3 table functions + Register(w)
  *_test.go                   offline CVSS tests + httptest-mock client/function tests
internal/mocknvd/
  server.go                   Handler(): serves canned NVD 2.0 JSON by query param
  data.go                     canned fixtures (Log4Shell, search/CPE records)
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
  `vgi.BindArgs`; do the network fetch here), `Process` (emit with `out.Emit`,
  then `out.Finish()`).

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
   `Process` (it may cross a process boundary), and the SDK now **panics at
   registration** if state isn't gob-encodable. So state `S` must have
   **exported, gob-encodable fields only** — no `arrow.Record`, no interfaces,
   channels, funcs, or unexported fields. The pattern every table function here
   uses: **fetch rows eagerly in `NewState`**, store plain exported Go slices
   (`Rows []CVERow`) plus a `Done bool`, and **rebuild the Arrow batch in
   `Process`**. `TestRegisterDoesNotPanic` guards against regressions.

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

## Mock-NVD E2E (how `make test-sql` works)

Mirrors `vgi-grpc`'s start/stop pattern:

1. `make build` compiles `vgi-cve-worker` **and** `mockserver`.
2. `mockserver --addr 127.0.0.1:0` binds a free port and prints `PORT:<n>`; the
   Makefile captures it.
3. The Makefile exports `VGI_CVE_WORKER` (the worker binary, the ATTACH
   `LOCATION`) and `VGI_CVE_TEST_URL=http://127.0.0.1:<n>/rest/json/cves/2.0`
   (read by `.test` files and passed as the `base_url` option).
4. `haybarn-unittest --test-dir . "test/sql/*"` runs the suite. Its exit status
   is captured so the `trap`'s SIGTERM to the mock doesn't mask success.
5. A shell `trap` kills the mock server and cleans up on exit.

`cmd/mockserver` and the Go tests share `internal/mocknvd.Handler()`, which
serves canned NVD 2.0 JSON keyed on query param: `cveId` (Log4Shell record or
404), `keywordSearch` (3 paginated records), `cpeName` (3 records incl. one with
no CVSS → NULL score).

## Test inventory

- **Go (`make test-unit`)** — `internal/cveworker/cvss_test.go` checks the
  severity bands and `BaseScore` against known vectors (9.8 / 10.0 / 7.5 /
  Scope:Changed) plus malformed-vector errors; `client_test.go` and
  `functions_test.go` run against `httptest` + `internal/mocknvd` and assert the
  `cve` parse, `cve_search` pagination, `cpe_cves` (incl. NULL score), and
  404/500/429/bad-JSON errors, plus the VGI `NewState` path and NULL→no-rows.
- **SQL (`make test-sql`)** — `test/sql/cvss_offline.test` (offline scalars, no
  mock needed) and `test/sql/cve_api.test` (table functions via the mock
  `base_url`, incl. an unknown-CVE `statement error`).

## Conventions

- Source files start with `// Copyright 2026 Query Farm LLC - https://query.farm`.
- `gofmt`, `go vet`, and `go test ./...` must be clean before committing.
- The worker is MIT-licensed; it uses only the Go stdlib for the NVD client and
  CVSS math, plus the vgi-go SDK for the protocol.
```
