// Copyright 2026 Query Farm LLC - https://query.farm

package mocknvd

// These types mirror the subset of the NVD 2.0 schema the worker reads. They
// are intentionally local to the mock so the canned fixtures read clearly.

type response struct {
	ResultsPerPage  int    `json:"resultsPerPage"`
	StartIndex      int    `json:"startIndex"`
	TotalResults    int    `json:"totalResults"`
	Vulnerabilities []vuln `json:"vulnerabilities"`
}

type vuln struct {
	CVE cveRecord `json:"cve"`
}

type cveRecord struct {
	ID           string       `json:"id"`
	Published    string       `json:"published"`
	LastModified string       `json:"lastModified"`
	Descriptions []langString `json:"descriptions"`
	Metrics      metrics      `json:"metrics"`
	Weaknesses   []weakness   `json:"weaknesses"`
}

type langString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type metrics struct {
	CVSSMetricV31 []cvssMetric `json:"cvssMetricV31,omitempty"`
}

type cvssMetric struct {
	Source   string   `json:"source"`
	Type     string   `json:"type"`
	CVSSData cvssData `json:"cvssData"`
}

type cvssData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type weakness struct {
	Source      string       `json:"source"`
	Type        string       `json:"type"`
	Description []langString `json:"description"`
}

func cwe(id string) []weakness {
	return []weakness{{
		Source: "nvd@nist.gov",
		Type:   "Primary",
		Description: []langString{
			{Lang: "en", Value: id},
		},
	}}
}

func v31(vector string, score float64, severity string) metrics {
	return metrics{CVSSMetricV31: []cvssMetric{{
		Source: "nvd@nist.gov",
		Type:   "Primary",
		CVSSData: cvssData{
			Version:      "3.1",
			VectorString: vector,
			BaseScore:    score,
			BaseSeverity: severity,
		},
	}}}
}

// log4Shell is a Log4Shell-shaped record (CVE-2021-44228): base score 10.0,
// CRITICAL, CWE-502.
var log4Shell = cveRecord{
	ID:           "CVE-2021-44228",
	Published:    "2021-12-10T10:15:09.143",
	LastModified: "2023-11-07T03:42:19.567",
	Descriptions: []langString{
		{Lang: "en", Value: "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints."},
	},
	Metrics:    v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
	Weaknesses: cwe("CWE-502"),
}

// byID indexes the records served by the cveId lookup.
var byID = map[string]cveRecord{
	log4Shell.ID: log4Shell,
}

// keywordRecords are returned (paginated) by keywordSearch. Three records so a
// resultsPerPage of 2 yields exactly two pages.
var keywordRecords = []cveRecord{
	log4Shell,
	{
		ID:           "CVE-2022-22965",
		Published:    "2022-04-01T23:15:12.510",
		LastModified: "2023-07-25T18:00:00.000",
		Descriptions: []langString{
			{Lang: "en", Value: "Spring Framework RCE via Data Binding on JDK 9+ (Spring4Shell)."},
		},
		Metrics:    v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
		Weaknesses: cwe("CWE-94"),
	},
	{
		ID:           "CVE-2014-0160",
		Published:    "2014-04-07T22:55:03.893",
		LastModified: "2023-11-07T02:18:10.043",
		Descriptions: []langString{
			{Lang: "en", Value: "The TLS heartbeat read overrun in OpenSSL (Heartbleed) allows remote attackers to obtain sensitive information."},
		},
		Metrics:    v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "HIGH"),
		Weaknesses: cwe("CWE-125"),
	},
}

// cpeRecords are returned (paginated) by a cpeName query. One of them carries
// no CVSS metrics, exercising the NULL-score path.
var cpeRecords = []cveRecord{
	log4Shell,
	{
		ID:           "CVE-2021-45046",
		Published:    "2021-12-14T19:15:07.733",
		LastModified: "2023-11-07T03:39:23.747",
		Descriptions: []langString{
			{Lang: "en", Value: "Incomplete fix for CVE-2021-44228 in certain non-default configurations."},
		},
		Metrics:    v31("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0, "CRITICAL"),
		Weaknesses: cwe("CWE-917"),
	},
	{
		// A record with no CVSS metrics: the worker must surface a NULL score.
		ID:           "CVE-2099-00000",
		Published:    "2099-01-01T00:00:00.000",
		LastModified: "2099-01-01T00:00:00.000",
		Descriptions: []langString{
			{Lang: "en", Value: "Awaiting analysis; no CVSS metrics assigned yet."},
		},
		Metrics:    metrics{},
		Weaknesses: nil,
	},
}
