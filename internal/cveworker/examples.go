// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"encoding/json"

	"github.com/Query-farm/vgi-go/vgi"
)

// Composed examples: queries that combine two or more of the worker's own
// objects. Each is defined ONCE here and referenced from every list that shows
// it — the schema-level vgi.example_queries (cmd/vgi-cve-worker/main.go), the
// example list of the object that drives the query, and (when offline and
// deterministic) the catalog's vgi.executable_examples.

// ExampleInventoryBands scores a small inventory of CVSS v3.1 vectors offline
// with cvss_base_score and buckets them with the cvss_severity_bands reference
// table, keeping empty bands as zero-count rows. Offline and deterministic.
var ExampleInventoryBands = vgi.CatalogExample{
	SQL: "WITH inventory(asset, vector) AS (VALUES " +
		"('web-01', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), " +
		"('db-01', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'), " +
		"('kiosk-01', 'CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'), " +
		"('app-02', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H')), " +
		"scored AS (SELECT asset, cve.main.cvss_base_score(vector) AS base_score FROM inventory) " +
		"SELECT b.severity, count(s.asset) AS assets, string_agg(s.asset, ', ' ORDER BY s.asset) AS asset_list " +
		"FROM cve.main.cvss_severity_bands b " +
		"LEFT JOIN scored s ON s.base_score BETWEEN b.min_score AND b.max_score " +
		"GROUP BY b.severity, b.min_score ORDER BY b.min_score;",
	Description: "Score an inventory of CVSS v3.1 vectors offline and count the assets in each " +
		"severity band, keeping empty bands as zero-count rows.",
}

// ExampleRescoreNVDVector fetches a CVE with cve() and recomputes its NVD
// vector offline with cvss_base_score to check NVD's published score.
var ExampleRescoreNVDVector = vgi.CatalogExample{
	SQL: "SELECT id, cvss_vector, cvss_score AS nvd_score, " +
		"cve.main.cvss_base_score(cvss_vector) AS recomputed_score, " +
		"cvss_score = cve.main.cvss_base_score(cvss_vector) AS scores_agree " +
		"FROM cve.main.cve('CVE-2021-44228') ORDER BY id;",
	Description: "Re-score Log4Shell's NVD CVSS v3.1 vector offline and check it reproduces " +
		"NVD's published base score.",
}

// ExampleSearchAffectsInstalled joins a cve_search keyword sweep to the
// cpe_cves list for one installed product version.
var ExampleSearchAffectsInstalled = vgi.CatalogExample{
	SQL: "SELECT s.id, s.cvss_score, s.cvss_severity, p.cve_id IS NOT NULL AS affects_2_14_1 " +
		"FROM cve.main.cve_search('log4j') s " +
		"LEFT JOIN cve.main.cpe_cves('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*') p ON p.cve_id = s.id " +
		"ORDER BY s.cvss_score DESC NULLS LAST, s.id;",
	Description: "Triage the log4j keyword-search hits: flag which ones NVD lists against the " +
		"installed Apache Log4j 2.14.1 CPE, most severe first.",
}

// ExamplePrioritizeCPE is the NVD + KEV + EPSS prioritization query: list
// the CVEs NVD records against an installed CPE, flag the ones CISA lists as
// known exploited, attach each CVE's EPSS exploitation probability, and rank
// exploited-first, then by EPSS, then by CVSS.
var ExamplePrioritizeCPE = vgi.CatalogExample{
	SQL: "WITH n AS (SELECT cve_id, cvss_score, cvss_severity " +
		"FROM cve.main.cpe_cves('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*')) " +
		"SELECT n.cve_id, n.cvss_score, n.cvss_severity, k.cve_id IS NOT NULL AS in_kev, " +
		"k.known_ransomware_campaign_use, e.epss, e.percentile " +
		"FROM n LEFT JOIN cve.main.kev() k ON k.cve_id = n.cve_id " +
		"LEFT JOIN cve.main.epss(['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105', 'CVE-2021-44832']) e " +
		"ON e.cve_id = n.cve_id " +
		"ORDER BY in_kev DESC, e.epss DESC NULLS LAST, n.cvss_score DESC NULLS LAST, n.cve_id;",
	Description: "Prioritize the CVEs affecting Apache Log4j 2.14.1: flag CISA known-exploited ones, " +
		"attach EPSS exploitation probability, and rank exploited-first, then by EPSS and CVSS.",
}

// ExampleOSVPackageInKEV expands an osv_query result's CVE aliases and flags
// the ones in the CISA KEV catalog.
var ExampleOSVPackageInKEV = vgi.CatalogExample{
	SQL: "WITH o AS (SELECT id, unnest(cve_ids) AS cve_id, database_severity, fixed_versions " +
		"FROM cve.main.osv_query('Maven', 'org.apache.logging.log4j:log4j-core', version := '2.14.1')) " +
		"SELECT o.id, o.cve_id, o.database_severity, k.cve_id IS NOT NULL AS in_kev, o.fixed_versions " +
		"FROM o LEFT JOIN cve.main.kev() k ON k.cve_id = o.cve_id ORDER BY in_kev DESC, o.id, o.cve_id;",
	Description: "Find the OSV advisories affecting log4j-core 2.14.1, expand their CVE ids, and flag " +
		"which are CISA known-exploited, with the versions that fix them.",
}

// ExampleQueriesJSON serializes examples as the JSON {description, sql} list
// carried by the vgi.example_queries / vgi.executable_examples tags. The
// worker entry point uses it too, so every list is built from the same
// CatalogExample values the functions use.
func ExampleQueriesJSON(examples ...vgi.CatalogExample) string {
	type describedExample struct {
		Description string `json:"description"`
		SQL         string `json:"sql"`
	}
	out := make([]describedExample, len(examples))
	for i, e := range examples {
		out[i] = describedExample{Description: e.Description, SQL: e.SQL}
	}
	b, err := json.Marshal(out)
	if err != nil {
		// The input is derived from static literals; a marshal error is a bug.
		panic(err)
	}
	return string(b)
}
