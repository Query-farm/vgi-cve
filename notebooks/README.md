# CVE score and vector notebooks

[01 · Keep the vector with the vulnerability score](01_keep_the_vector_with_the_score.ipynb)
retrieves three NVD records through the real VGI worker, recomputes CVSS v3.1
base scores offline and compares the metric tokens behind them. Two charts show
reported/recomputed scores and vector differences. A configurable cutoff creates
an explicitly bounded review queue while retaining unavailable records.

## Run from this directory

Install [uv](https://docs.astral.sh/uv/), then:

```sh
cd notebooks
uv sync --locked
uv run --locked python execute.py
```

In a notebook editor, select `notebooks/.venv/bin/python` and run all cells. The
locked Python 3.13–3.14 environment uses Haybarn 2.0.0rc11, JupySQL, Seaborn and
Matplotlib. The complete notebook directory runs outside the worker checkout;
no local Go build or root source package is required.

The worker connection is a literal visible SQL cell:

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'cve' (TYPE vgi,
 LOCATION 'github-auto://Query-farm/vgi-cve@v0.4.0');
```

Haybarn downloads, verifies and caches the platform release. Public v0.4.0 assets
cover macOS arm64, Linux amd64/arm64 and Windows amd64; validation here used macOS
arm64. Initial downloads need network access. Change the visible release pin and
rerun the examples when upgrading. Parameters and analytical SQL remain expanded;
setup, plotting and cleanup are folded with useful outputs visible. Official local
Strata Sun branding appears at both ends, and the VGI logo links to the product.

## Recorded data, live data and experiments

`DATA_MODE = "recorded"` is the default. A loopback-only Python server returns the
unmodified official JSON bodies under `fixtures/` through the worker's documented
`base_url` option. It verifies SHA-256 digests, rejects requests outside the three
recorded IDs and audits that each is requested once. The worker performs all API
projection and score computation. Recording never replaces a failed live request.

The fixed cohort is CVE-2021-44228, CVE-2021-45046 and CVE-2021-45105. Responses
were captured from the official NVD API on 2026-11-14 UTC. Exact URLs, capture
instants, capture-clock descriptions and hashes are in [the manifest](fixtures/manifest.json).
They are separate responses, not an atomic snapshot. The notebook retains NVD's
published/last-modified strings as returned and displays capture provenance separately.

`SCORE_FLOOR` accepts finite numbers from 0 to 10 inclusive. The default is 9.0.
To lower only that cutoff without replacing the saved default:

```sh
uv run --locked python execute.py --parameters '{"SCORE_FLOOR":4.0}' \
  --output-dir validation/floor-4
```

`DATA_MODE = "live"` makes the same three unauthenticated requests directly to
NVD. Source data can change; rate limits, timeouts and HTTP failures remain errors.
This mode does not load recorded response bodies or fall back to them.

```sh
uv run --locked python execute.py --parameters '{"DATA_MODE":"live"}' \
  --output-dir validation/live
```

During validation, an actual released-worker live lookup succeeded, while broader
live metadata probes encountered NVD HTTP 503 responses. The complete live
notebook attempt also stopped on HTTP 503; no successful live copy was saved,
and the saved default remained unchanged. Recorded mode remains
repeatable during upstream outages. Successful recorded tests do not imply that
NVD's public endpoint is continuously available.

The runner starts fresh kernels, saves only successful execution and requires a
separate destination for overrides. It rejects unknown names and source-directory
overwrites. Copies include assets, recordings, helpers, this guide and the locked
environment. Generated artifacts and copies under `validation/` are ignored; the
main notebook retains its successful embedded outputs.

## Interpret the comparison

The pinned worker projects the first CVSS v3.1 metric, otherwise the first v3.0,
otherwise v2. It does not aggregate assessments or expose every metric source;
raw responses retain that provenance. CVSS v4 metrics are outside this worker's
projection. A missing projected score must not be assumed to mean NVD has no
other assessment. This notebook recomputes only explicit v3.1 vectors and keeps
other versions outside that arithmetic path.

A left join preserves every requested identifier. A record not returned, an
unavailable metric and a different CVSS version receive separate labels. The
score plot never substitutes zero for unavailable values. The metric matrix
highlights columns with differing observed tokens; its colors are not numerical
severity weights. Selection uses the reported score and requires a comparable
v3.1 vector. Recomputed-score differences remain visible for review rather than
being silently overwritten or asserted away.

Separate synthetic controls demonstrate NULL, a valid zero-impact vector and an
excluded v2 vector. They are not merged into the NVD cohort. The offline worker
computes Base scores; Temporal and Environmental scoring is outside this example.
The three-ID set is neither a complete product vulnerability list nor an asset
remediation plan. NVD data is courtesy of NIST/NVD; this example is not endorsed
by NIST.

References: [NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities),
[FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document),
[worker documentation](https://github.com/Query-farm/vgi-cve),
[pinned release](https://github.com/Query-farm/vgi-cve/releases/tag/v0.4.0).
