# CVE & CVSS notebooks

| Notebook | Question | Experiment |
| --- | --- | --- |
| [01 · Keep the vector with the vulnerability score](01_keep_the_vector_with_the_score.ipynb) | Do returned vectors reproduce reported scores, and which records meet a chosen cutoff? | `SCORE_FLOOR`: 9 → 4 |
| [02 · Compare keyword and product membership](02_compare_keyword_and_product_membership.ipynb) | How do two query populations differ, and which product records meet a band cutoff? | `MIN_BAND`: `HIGH` → `MEDIUM` |

Each notebook is independent, with visible analytical SQL, a concrete experiment,
and two SVG figures. Notebook 01 retains genuine recorded NVD responses. Notebook 02
uses entirely synthetic pages and fictional identifiers; it makes no factual claim
about vulnerabilities or affected products.

## Run and change parameters

Install [uv](https://docs.astral.sh/uv/), then run from this directory:

```sh
uv sync --locked
uv run --locked vgi-notebooks --timeout 600
uv run --locked vgi-notebooks 01_keep_the_vector_with_the_score.ipynb \
  --parameters '{"SCORE_FLOOR":4}' --output-dir artifacts/floor-4
uv run --locked vgi-notebooks 02_compare_keyword_and_product_membership.ipynb \
  --parameters '{"MIN_BAND":"MEDIUM"}' --output-dir artifacts/medium
```

The local environment pins [shared v0.3.42](https://github.com/Query-farm/vgi-example-notebooks/tree/v0.3.42) with its `[runner]` extra;
Haybarn is 2.0.0rc11. Colab links are included above each story. Their bootstrap
installs only the shared base package, checks preloaded libraries and downloads
hash-verified companions through the `cve` registry. The registry pins eleven files
at `dc5ec274228c4f9774416448db0bee28101028b9`; no worker checkout is needed.
The runner preserves successful defaults and requires a separate destination for
parameter overrides. SVGs display natively in Jupyter/Colab; saved content-addressed
image links serve GitHub's notebook renderer.

Both notebooks use this visible release connection:

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'cve' (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-cve@v0.4.0');
```

Public v0.4.0 resolves to `89ea9615fc87b32fb0268d5681a21547e9698da5` and provides
native macOS arm64, Linux amd64/arm64 and Windows amd64 assets. Haybarn downloads,
verifies and caches the matching executable. Validation here uses macOS arm64;
initial setup needs network access. No compilation is part of notebook startup.

Shared setup creates a fresh empty temporary SQL-secret directory, disables
persistent secrets and establishes UTC on the parent connection before loading SQL
magics. Empty inventories are checked before use and at cleanup. No API keys or SQL
secrets are created, loaded or altered. All API calls are materialized before
DataFrame capture, so display does not fetch them twice.

## Sources and boundaries

Notebook 01 preserves the three original official NVD response bodies and their
[manifest](fixtures/manifest.json) unchanged. They were captured independently on
2026-11-14 UTC for CVE-2021-44228, CVE-2021-45046 and CVE-2021-45105. The loopback
server verifies SHA-256 hashes, accepts only those exact requests and audits one
request per ID. The actual released worker parses the bodies and computes scores.
Capture timestamps and NVD publication/modification strings remain distinct.
These independent responses are not an atomic snapshot or a historical release
vintage. Data is courtesy of NIST/NVD; this example is not endorsed by NIST.

Notebook 02's [synthetic page guide](synthetic_search/README.md) and
[manifest](synthetic_search/manifest.json) specify all fictional inputs. Keyword
membership is five IDs; product membership is four, with three shared IDs. The
server returns at most two records per page while the worker requests fifty, making
its actual offset progression observable. Fixed byte responses perform no search,
filtering, score calculation, join or band selection. All such analysis is visible
SQL over real worker results. The worker stops at 100 rows on broader queries;
absence from a bounded result does not prove absence from NVD or lack of relevance.

The release projects the first v3.1 metric, otherwise the first v3.0, otherwise v2.
It does not expose every assessment or project CVSS v4. Notebook 01 recomputes only
explicit v3.1 vectors and keeps other versions outside that path. Missing projected
scores do not imply that no other assessment exists in the raw source.

One source/release difference remains explicit: current source turns missing
severity/vector strings into SQL NULL; release v0.4.0 returns empty strings beside
an absent numeric score. Notebook 02 displays the raw severity and derives
`Unscored` from the numeric NULL in SQL. It never substitutes zero for missingness.
The genuine zero in the synthetic keyword result belongs to the `NONE` band.

CVSS Base describes vulnerability characteristics, not local asset exposure,
exploitation probability or business impact. This fixed cohort and local threshold
are not a complete product assessment or remediation plan. Reference counts,
keyword matches and product associations are not equivalent measures of urgency.

## Optional live lookup

Notebook 01 alone supports explicit live retrieval of its three genuine CVE IDs:

```sh
uv run --locked vgi-notebooks 01_keep_the_vector_with_the_score.ipynb \
  --parameters '{"DATA_MODE":"live"}' --output-dir artifacts/live --timeout 600
```

Live mode uses the official HTTPS endpoint without credentials or recording fallback.
Failures remain errors. The full three-ID live notebook passed during this revision; its displayed scores,
vectors and source timestamps agreed with the saved recordings. A separate bounded
public keyword capture returned HTTP 503 on its first request and was stopped without
retry. Live lookup success and search availability are distinct observations. Notebook 02 has no live mode for fictional inputs. A successful synthetic
or recorded run does not establish public service availability.

## Coverage and verification

[coverage.json](coverage.json) binds visible SQL, results, narrative interpretation
and successful execution receipts to all **six distinct public names**. The release
catalog comes from actual complete `duckdb_functions`, `duckdb_tables` and
`duckdb_views` exports. The five functions and severity-band relation form six
surfaces; no public handler or authenticated surface is excluded.

The current-public snapshot at `2aaebb2046171a0b28875f1c1ccc076fdb4254b7` is verified
against complete registration sources and their release delta, with unchanged
names/signatures. It is source evidence, not a current-binary run: current catalog
`collection_reconciled` is false and exact-current runtime coverage is zero. The
local preexisting binary has dirty historical provenance and was not represented
as current. Actual analytical execution uses the published release.

Unchanged worker source reuses its [green source CI](https://github.com/Query-farm/vgi-cve/actions/runs/43565667741).
No worker rebuild, source-suite repeat or container publication is required for
these notebook changes. Default and parameter runs, request audits, contract checks,
preloaded base-only startup, output/figure reviews and GitHub SVG rendering are
validated separately. A local preloaded-kernel test is not a manually executed
hosted Colab session.

Background: [NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities),
[FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document).
