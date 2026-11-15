# Synthetic keyword and product responses

These five NVD-shaped JSON pages are entirely synthetic. CVE-2099-90001 through
CVE-2099-90006 and the example widget CPE are fictional teaching inputs. They are
not observations, vulnerabilities, affected products or NVD assessments.

Keyword membership is 1, 2, 3, 4, 5; product membership is 2, 3, 5, 6. Record 5 has
no metrics; record 4 has a genuine numeric zero within this synthetic scenario.
Responses return at most two rows while the real worker requests fifty. This makes
its actual pagination visible: offsets 0, 2, 4 for keyword and 0, 2 for product.
The server returns fixed bytes by the exact request; it does not compute joins,
severity bands, filtering or scores. The manifest binds each page by SHA-256.

An unauthenticated live keyword recording attempt returned NVD HTTP 503 during this
revision. This synthetic story is a separate, explicit data source; it is not a
fallback secretly substituted for a failed live run. Notebook 01 retains its own
unmodified official recordings and optional live mode.
