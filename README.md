<p align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi/main/docs/vgi-logo.png" alt="Vector Gateway Interface (VGI)" width="320">
</p>

<p align="center"><em>A <a href="https://query.farm">Query.Farm</a> VGI worker for DuckDB.</em></p>

# vgi-cve

[![CI](https://github.com/Query-farm/vgi-cve/actions/workflows/ci.yml/badge.svg)](https://github.com/Query-farm/vgi-cve/actions/workflows/ci.yml)

A [VGI](https://query.farm) worker, written in **Go**, that looks up
**CVE / vulnerability data** from the [NVD 2.0 API](https://nvd.nist.gov/developers/vulnerabilities)
and computes **CVSS v3.1 scores** — all exposed as DuckDB/SQL functions. It is a
defensive vulnerability-management tool.

Built on the [`vgi-go`](https://github.com/Query-farm/vgi-go) SDK; speaks the
VGI protocol over stdio. Catalog name: `cve`.

```sql
INSTALL vgi FROM community; LOAD vgi;

-- LOCATION is the path to the compiled worker binary.
ATTACH 'cve' AS cve (TYPE vgi, LOCATION '/path/to/vgi-cve-worker');

-- Offline CVSS math (no network):
SELECT cve.cvss_base_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'); -- 9.8
SELECT cve.cvss_severity(9.8);                                              -- CRITICAL

-- Look up a CVE from the NVD API:
SELECT id, cvss_score, cvss_severity, cwe FROM cve.cve('CVE-2021-44228');

-- Keyword search (paginated, bounded to 100 results):
SELECT id, cvss_severity, published FROM cve.cve_search('log4j');

-- CVEs affecting a CPE name:
SELECT cve_id, cvss_score, cvss_severity
FROM cve.cpe_cves('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*');
```

## Functions

There are two families: **offline scalars** (pure CVSS math, no network,
deterministic) and **table functions** (live NVD 2.0 API lookups).

### Offline CVSS scalars (no network)

| Function | Returns | Description |
| --- | --- | --- |
| `cvss_severity(score DOUBLE)` | `VARCHAR` | Map a base score to `NONE`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL` per the CVSS v3 bands. |
| `cvss_base_score(vector VARCHAR)` | `DOUBLE` | Compute the CVSS v3.1 base score from a vector string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → `9.8`). Implements the official v3.1 base equation, including the changed-scope path and the spec "Roundup". |

### NVD 2.0 table functions (network)

| Function | Returns | Description |
| --- | --- | --- |
| `cve(cve_id)` | `id, description, cvss_score DOUBLE, cvss_severity VARCHAR, cvss_vector, published, last_modified, cwe` | Fetch one CVE by ID (one row, or zero rows for a NULL id). |
| `cve_search(keyword)` | `id, description, cvss_score, cvss_severity, published` | Keyword search of CVE descriptions; paginated, bounded to 100 results. |
| `cpe_cves(cpe)` | `cve_id, cvss_score, cvss_severity` | CVEs affecting a CPE 2.3 name; paginated, bounded. |

A CVE with no CVSS metrics yields a **NULL** `cvss_score`.

### Named options (table functions)

Every table function accepts the same optional named arguments (DuckDB
`name := value` syntax):

| Option | Default | Meaning |
| --- | --- | --- |
| `base_url` | the real NVD endpoint | Override the NVD 2.0 base URL (used to point at a mock/proxy). |
| `api_key` | `''` | NVD API key, sent as the `apiKey` header. Raises NVD's rate limit. |

```sql
SELECT id, cvss_score
FROM cve.cve('CVE-2021-44228', api_key := 'your-nvd-key');
```

## Behavior & robustness

- **Offline first.** `cvss_severity` and `cvss_base_score` make no network call
  and are fully deterministic — ideal for scoring vectors already in your data.
- **NULL / absent input → no rows.** A NULL id/keyword/cpe yields zero rows.
- **No CVSS metrics → NULL score.** Records still under analysis surface a NULL
  `cvss_score` rather than a misleading `0`.
- **Bounded & timed.** Searches page through results but stop at 100 rows; every
  HTTP call has a 30 s timeout, so a slow or unreachable endpoint fails fast.
- **Clear errors, never a crash or hang.** HTTP 4xx/5xx, NVD rate-limiting
  (429), an unknown CVE id (404), or malformed JSON all surface as a clean
  DuckDB error.

## Build

Requires Go 1.25+.

```sh
make build        # builds ./vgi-cve-worker and ./mockserver
```

The `vgi-cve-worker` binary speaks the VGI protocol over stdio; point a DuckDB
`ATTACH ... (TYPE vgi, LOCATION '…')` at it.

## Test

```sh
make test-unit    # pure-Go unit tests (offline CVSS + httptest mock NVD)
make test-sql     # haybarn-unittest SQL end-to-end against a local mock NVD
make test         # both
```

`make test-sql` needs [`haybarn-unittest`](https://query.farm) on `PATH`:

```sh
uv tool install haybarn-unittest
export PATH="$HOME/.local/bin:$PATH"
```

It builds the worker and a small **mock NVD server** (`cmd/mockserver`, serving
canned NVD 2.0 JSON), starts the mock on a free port, points the table functions
at it via the `base_url` option, runs the suite, and stops the mock.

## NVD API terms & rate limits

This worker calls the public **NVD 2.0** vulnerability API operated by NIST.
Please respect the [NVD terms of use](https://nvd.nist.gov/developers/terms-of-use)
and rate limits: unauthenticated clients are throttled aggressively (roughly a
handful of requests per rolling 30 s window). Request a free
[NVD API key](https://nvd.nist.gov/developers/request-an-api-key) and pass it via
`api_key := '…'` to raise the limit. CVE data is courtesy of NIST/NVD; this
project is not endorsed by or affiliated with NIST.

## Licensing

- This worker is licensed **MIT** — see [`LICENSE`](./LICENSE).
- It uses only the Go **standard library** (`net/http`, `encoding/json`) for the
  NVD client and CVSS math, plus the [`vgi-go`](https://github.com/Query-farm/vgi-go)
  SDK (and its Arrow dependency) for the VGI protocol — see that repo for its
  terms.

---

## Authorship & License

Written by [Query.Farm](https://query.farm).

Copyright 2026 Query Farm LLC - https://query.farm

