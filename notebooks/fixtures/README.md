# Recorded NVD responses

These are unmodified HTTP response bodies from the official NVD CVE 2.0 endpoint,
retrieved for the three exact URLs in `manifest.json`. Each recording contains one
requested CVE. The manifest records capture time, its clock source, byte length,
HTTP status and SHA-256. JSON files are marked `-text` to preserve the exact bytes.
The first capture's timestamp comes from the response file write time; later
capture times were measured at response-read completion.

`nvd_replay.py` verifies each digest before serving it on loopback. It accepts only
the exact recorded `cveId` requests. Nothing is fetched from NVD in recorded mode,
and no failed live request falls back to these files. Full records preserve all
original metric entries, source identities and timestamps, although the worker
projects only its preferred metric. Synthetic NULL/zero/version controls live in
the notebook SQL and are not part of these responses.

Source: [NIST National Vulnerability Database](https://nvd.nist.gov/).
Data is courtesy of NIST/NVD. This example is not endorsed by NIST.
