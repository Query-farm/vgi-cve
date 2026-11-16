<p align="center">
  <img src="https://query.farm/media-kit/products/vgi/vgi-logo.png" alt="Vector Gateway Interface (VGI)" width="320">
</p>

<p align="center"><em>A <a href="https://query.farm">Query.Farm</a> VGI worker for DuckDB.</em></p>

# CVE Lookup, Exploit Prioritization & CVSS Scoring in DuckDB

> **vgi-cve** · a [Query.Farm](https://query.farm) VGI worker

[![CI](https://github.com/Query-farm/vgi-cve/actions/workflows/ci.yml/badge.svg)](https://github.com/Query-farm/vgi-cve/actions/workflows/ci.yml)

A [VGI](https://query.farm) worker, written in **Go**, that looks up
**CVE / vulnerability data** from the [NVD 2.0 API](https://nvd.nist.gov/developers/vulnerabilities)
, flags **known-exploited CVEs** from the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
scores **exploit likelihood** with [FIRST EPSS](https://www.first.org/epss/),
finds **open-source package advisories** on [OSV.dev](https://osv.dev), and
computes **CVSS v3.1 scores** — all exposed as DuckDB/SQL functions. It is a
defensive vulnerability-management tool.

Built on the [`vgi-go`](https://github.com/Query-farm/vgi-go) SDK; speaks the
VGI protocol over stdio. Catalog name: `cve`.

```sql
INSTALL vgi FROM community; LOAD vgi;

ATTACH 'cve' AS cve (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-cve@v0.5.2');

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

-- Is it actively exploited (CISA KEV)? How likely is exploitation (EPSS)?
SELECT cve_id, date_added, known_ransomware_campaign_use FROM cve.kev_cve('CVE-2021-44228');
SELECT cve_id, epss, percentile FROM cve.epss(['CVE-2021-44228', 'CVE-2022-22965']);

-- Advisories affecting an open-source package version (OSV.dev):
SELECT id, cve_ids, fixed_versions FROM cve.osv_query('PyPI', 'jinja2', version := '2.4.1');
```

## Executed notebooks

See [the SQL and visualization examples](notebooks/README.md) for a portable,
executed walkthroughs of recorded NVD lookups, CVSS vectors and score comparisons,
plus an explicit synthetic keyword-versus-product membership exercise.

## Quick start

Every [GitHub release](https://github.com/Query-farm/vgi-cve/releases) ships a prebuilt worker binary. The `vgi` extension downloads the one for your platform, checks its SHA-256 and caches it, so there is nothing to install besides DuckDB:

```sql
INSTALL vgi FROM community;
LOAD vgi;

ATTACH 'cve' AS cve (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-cve@v0.5.2');

-- Compute the CVSS v3.1 base score for the Log4Shell vector (9.8).
SELECT cve.main.cvss_base_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');

-- Map a numeric CVSS base score to its qualitative severity band (CRITICAL).
SELECT cve.main.cvss_severity(9.8);
```

The offline CVSS scalars need no network. The NVD table functions (`cve`, `cve_search`, `cpe_cves`) call the public NVD 2.0 API, which throttles unauthenticated clients; pass a free NVD key with `api_key := '…'` to raise the limit. See [NVD API terms & rate limits](#nvd-api-terms--rate-limits).

Prebuilt binaries cover macOS (Apple silicon), Linux (x86-64 and arm64) and Windows (x86-64). `github-auto://` needs an explicit release tag; change `@v0.5.2` to move to a newer release.

### Other ways to run it

- **Docker** (the image bundles the worker; needs a container runtime):

  ```sql
  ATTACH 'cve' AS cve (TYPE vgi, LOCATION 'docker://ghcr.io/query-farm/vgi-cve:0.5.2');
  ```

- **Manual download.** Download the archive for your platform from the [releases page](https://github.com/Query-farm/vgi-cve/releases), verify it against its `.sha256` file (a cosign `.cosign.bundle` is published alongside), unpack it, and set `LOCATION` to the path of the extracted worker executable.

### Build from source

To build the worker yourself, see [Build](#build).

## Functions

There are four families: **offline scalars** (pure CVSS math, no network,
deterministic), **NVD 2.0 lookups**, **exploit intelligence** (CISA KEV + FIRST
EPSS), and **OSV.dev open-source advisories**. Every network function is a
table function that takes a `base_url` override.

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
| `cpe_cves(cpe)` | `cve_id, description, cvss_score, cvss_severity, published` | CVEs affecting a CPE 2.3 name; paginated, bounded. |

A CVE with no CVSS metrics yields a **NULL** `cvss_score` (and NULL
`cvss_severity` / `cvss_vector`). `cvss_vector` is the vector NVD scored: v3.1
when present, else v3.0, else v2; `cvss_base_score` accepts only the v3.x forms.

The two families compose. Re-score a fetched CVE's vector offline and check it
reproduces NVD's published score:

```sql
SELECT id, cvss_vector, cvss_score AS nvd_score,
       cve.main.cvss_base_score(cvss_vector) AS recomputed_score,
       cvss_score = cve.main.cvss_base_score(cvss_vector) AS scores_agree
FROM cve.main.cve('CVE-2021-44228')
ORDER BY id;
```

### Exploit intelligence: CISA KEV and FIRST EPSS (network)

| Function | Returns | Description |
| --- | --- | --- |
| `kev()` | `cve_id, vendor_project, product, vulnerability_name, date_added DATE, short_description, required_action, due_date DATE, known_ransomware_campaign_use, notes, cwes VARCHAR[]` | The whole CISA Known Exploited Vulnerabilities catalog (~1,800 rows). The feed is cached in-process for 15 minutes, so joining `kev()` several times in one session fetches it once. |
| `kev_cve(cve_id)` | same columns as `kev()` | The KEV entry for one CVE (case-insensitive), or **zero rows** when it isn't listed, so `count(*) > 0` is an "is it exploited?" test. |
| `epss(cve_ids VARCHAR[], date := '')` | `cve_id, epss DOUBLE, percentile DOUBLE, date DATE` | FIRST EPSS probability (0–1) that each CVE is exploited in the next 30 days, plus its percentile. `date := 'YYYY-MM-DD'` returns historical scores. Ids are deduplicated and batched into as few requests as the API's 2000-character `cve=` limit allows (about 140 ids per request, paged with `offset`); at most 10,000 ids per call. CVEs EPSS has no score for are left out. |

```sql
-- Most recently added KEV entries used in ransomware campaigns
SELECT cve_id, vendor_project, product, date_added, due_date
FROM cve.kev() WHERE known_ransomware_campaign_use = 'Known'
ORDER BY date_added DESC LIMIT 10;

-- Log4Shell's EPSS score on 2023-03-01
SELECT cve_id, epss, percentile FROM cve.epss(['CVE-2021-44228'], date := '2023-03-01');
```

DuckDB doesn't allow subqueries as table-function arguments, so to score a
dynamic set of CVEs, put the list in a variable first:

```sql
SET VARIABLE ids = (SELECT list(cve_id) FROM cve.kev() WHERE vendor_project = 'Apache');
SELECT * FROM cve.epss(getvariable('ids')) ORDER BY epss DESC;
```

### Open-source advisories: OSV.dev (network)

| Function | Returns | Description |
| --- | --- | --- |
| `osv_query(ecosystem, name, version := '')` | `id, summary, details, aliases VARCHAR[], cve_ids VARCHAR[], cvss_vector, database_severity, published, modified, withdrawn, affected_packages VARCHAR[], affected_ranges VARCHAR[], fixed_versions VARCHAR[]` | Advisories affecting a package (`'PyPI'`, `'npm'`, `'Maven'`, `'Go'`, `'crates.io'`, ...). With `version :=` only those affecting that exact version. `affected_ranges`/`fixed_versions` cover the queried package only. Follows `next_page_token`, stops at 1,000 rows, sorted by id. |
| `osv_vuln(id)` | same columns as `osv_query` | One OSV record by id: `GHSA-…`, `PYSEC-…`, `GO-…`, `RUSTSEC-…`, `CVE-…`, and so on. Ranges and fixes cover every affected package. **Zero rows** for an unknown id. |

`cve_ids` holds the `CVE-` ids found in `id` and `aliases`. It's the column to
join against `cve()`, `kev()` and `epss()`. `cvss_vector` prefers a v3.x vector
(the form `cvss_base_score` can score), then falls back to v4 or v2.
`affected_ranges` reads like `'>=2.13.0 <2.15.0'` or `'<2.10.1'`, and git
commit ranges are left out.

```sql
SELECT id, cvss_vector, cve.cvss_base_score(cvss_vector) AS base_score
FROM cve.osv_vuln('GHSA-462w-v97r-4m45');   -- 8.6
```

### Putting it together: what to patch first

CVSS tells you how bad a CVE could be. KEV tells you it **is** being exploited,
and EPSS tells you how **likely** exploitation is. This query ranks the CVEs NVD
lists against an installed Log4j: KEV-listed ones first, then by EPSS, then by
CVSS.

```sql
WITH n AS (
  SELECT cve_id, cvss_score, cvss_severity
  FROM cve.main.cpe_cves('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'))
SELECT n.cve_id, n.cvss_score, n.cvss_severity,
       k.cve_id IS NOT NULL AS in_kev, k.known_ransomware_campaign_use,
       e.epss, e.percentile
FROM n
LEFT JOIN cve.main.kev() k ON k.cve_id = n.cve_id
LEFT JOIN cve.main.epss(['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105', 'CVE-2021-44832']) e
       ON e.cve_id = n.cve_id
ORDER BY in_kev DESC, e.epss DESC NULLS LAST, n.cvss_score DESC NULLS LAST, n.cve_id;
```

The same approach works for a dependency. Expand the CVE aliases of the OSV
advisories that affect it, then flag the KEV-listed ones:

```sql
WITH o AS (
  SELECT id, unnest(cve_ids) AS cve_id, database_severity, fixed_versions
  FROM cve.main.osv_query('Maven', 'org.apache.logging.log4j:log4j-core', version := '2.14.1'))
SELECT o.id, o.cve_id, o.database_severity, k.cve_id IS NOT NULL AS in_kev, o.fixed_versions
FROM o LEFT JOIN cve.main.kev() k ON k.cve_id = o.cve_id
ORDER BY in_kev DESC, o.id, o.cve_id;
```

### Named options (table functions)

Every network table function accepts a `base_url` named argument (DuckDB
`name := value` syntax) that redirects it to a mirror, a proxy, or the test
mock. The NVD functions also take `api_key`:

| Option | Applies to | Default | Meaning |
| --- | --- | --- | --- |
| `base_url` | `cve`, `cve_search`, `cpe_cves` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | The NVD 2.0 CVE endpoint. |
| `base_url` | `kev`, `kev_cve` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | The whole KEV JSON feed URL. |
| `base_url` | `epss` | `https://api.first.org/data/v1/epss` | The EPSS API endpoint. |
| `base_url` | `osv_query`, `osv_vuln` | `https://api.osv.dev/v1` | The OSV API root (`/query` and `/vulns/{id}` are appended). |
| `api_key` | NVD functions | `''` | NVD API key, sent as the `apiKey` header. Raises NVD's rate limit. |

```sql
SELECT id, cvss_score
FROM cve.cve('CVE-2021-44228', api_key := 'your-nvd-key');
```

## Behavior & robustness

- **Offline first.** `cvss_severity` and `cvss_base_score` make no network call
  and are fully deterministic — ideal for scoring vectors already in your data.
- **NULL / blank input → no rows.** A NULL or empty id/keyword/cpe/package
  yields zero rows without making a request, and so does an empty `epss([])` list. An id that isn't listed is zero
  rows for `kev_cve` and `osv_vuln`, while `cve()` raises a 404 error.
- **No CVSS metrics → NULL score.** Records still under analysis surface a NULL
  `cvss_score` (and NULL `cvss_severity` / `cvss_vector`) rather than a
  misleading `0` or empty string.
- **Bounded & timed.** NVD searches stop at 100 rows, `osv_query` at 1,000 rows,
  and `epss` at 10,000 ids per call. Every HTTP call has a 30 s timeout, so a
  slow or unreachable endpoint fails fast.
- **Clear errors, never a crash or hang.** HTTP 4xx/5xx, rate limiting (429),
  an unknown NVD CVE id (404), or malformed JSON all surface as a clean DuckDB
  error, prefixed with the source (`nvd:`, `kev:`, `epss:`, `osv:`).

## Build

Requires Go 1.26+.

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

`make test-sql` installs the pinned `haybarn-unittest` SQL runner into `.tools`
(needs [uv](https://docs.astral.sh/uv/)) and runs `test/sql` over every DuckDB
transport — stdio, launch (a DuckDB-managed AF_UNIX socket) and http — through
[`ci/run-integration.sh`](ci/run-integration.sh); `make test-sql TRANSPORTS=http`
runs one.

It builds the worker and a small **mock server** (`cmd/mockserver`). The mock
serves canned NVD 2.0, CISA KEV, FIRST EPSS and OSV.dev JSON at the same paths
as the real services. The target starts the mock on a free port, points every
table function at it through `base_url`, runs the suite, and stops the mock.
No test touches the real internet.

## NVD API terms & rate limits

This worker calls the public **NVD 2.0** vulnerability API operated by NIST.
Please respect the [NVD terms of use](https://nvd.nist.gov/developers/terms-of-use)
and rate limits: unauthenticated clients are throttled aggressively (roughly a
handful of requests per rolling 30 s window). Request a free
[NVD API key](https://nvd.nist.gov/developers/request-an-api-key) and pass it via
`api_key := '…'` to raise the limit. CVE data is courtesy of NIST/NVD; this
project is not endorsed by or affiliated with NIST.

## KEV, EPSS & OSV data terms and attribution

- **CISA KEV:** the Known Exploited Vulnerabilities catalog is published by
  the US Cybersecurity and Infrastructure Security Agency. As a US government
  work it is in the public domain. This project is not endorsed by or
  affiliated with CISA.
- **FIRST EPSS:** EPSS scores are produced by the [EPSS SIG at FIRST](https://www.first.org/epss/)
  and are free to use. FIRST asks users to cite EPSS when they use it, e.g.
  "Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman, Idris Adjerid,
  (2021), Exploit Prediction Scoring System, Digital Threats Research and
  Practice, 2(3)" — see the [EPSS usage guidance](https://www.first.org/epss/user-guide).
  The public API is rate limited (roughly 1,000 requests a minute). `epss()`
  packs about 140 CVEs into each request.
- **OSV.dev:** OSV data is available under
  [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/). Individual source
  databases (GitHub Advisory Database, PyPI, Go, RustSec, ...) may set their own
  terms, so check the source named in each record before you redistribute it.
  Data courtesy of [OSV.dev](https://osv.dev).

## Licensing

- This worker is licensed **MIT** — see [`LICENSE`](./LICENSE).
- It uses only the Go **standard library** (`net/http`, `encoding/json`) for the
  NVD/KEV/EPSS/OSV clients and CVSS math, plus the [`vgi-go`](https://github.com/Query-farm/vgi-go)
  SDK (and its Arrow dependency) for the VGI protocol — see that repo for its
  terms.

---

## Authorship & License

Written by [Query.Farm](https://query.farm).

Copyright 2026 Query Farm LLC - https://query.farm

