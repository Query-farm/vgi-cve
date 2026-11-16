// Copyright 2026 Query Farm LLC - https://query.farm

package mocknvd

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// OSVPrefix is the OSV API root the mock serves (/v1/query, /v1/vulns/{id}),
// matching api.osv.dev/v1.
const OSVPrefix = "/v1"

// OSVPageSize is the mock's page size for /v1/query; a package with more
// matching records than this is split across next_page_token pages.
const OSVPageSize = 2

// osvRecordsJSON are OSV-schema records: two log4j-core advisories (Maven)
// and three jinja2 advisories (PyPI), one of which has no severity (NULL
// cvss_vector) and only a PYSEC id with a CVE alias.
var osvRecordsJSON = []string{
	`{"id":"GHSA-jfh8-c2jp-5v3q","summary":"Remote code injection in Log4j","details":"Logging untrusted data with log4j versions 2.0-beta9 through 2.14.1 can result in a remote code execution (RCE) vulnerability when the attacker controls an LDAP or other JNDI endpoint.","aliases":["CVE-2021-44228"],"modified":"2025-05-09T12:28:41Z","published":"2021-12-10T00:40:56Z","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],"affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core","purl":"pkg:maven/org.apache.logging.log4j/log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.15.0"}]},{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.3.1"}]},{"type":"ECOSYSTEM","events":[{"introduced":"2.4"},{"fixed":"2.12.2"}]}],"versions":["2.13.0","2.13.1","2.13.2","2.13.3","2.14.0","2.14.1","2.11.0","2.12.0","2.12.1"]}],"database_specific":{"cwe_ids":["CWE-20","CWE-400","CWE-502","CWE-917"],"severity":"CRITICAL","github_reviewed":true}}`,
	`{"id":"GHSA-7rjr-3q55-vv33","summary":"Incomplete fix for Apache Log4j vulnerability","details":"The fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations.","aliases":["CVE-2021-45046"],"modified":"2025-05-09T12:28:41Z","published":"2021-12-14T18:01:28Z","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"}],"affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.16.0"}]},{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.12.2"}]}],"versions":["2.13.0","2.14.0","2.14.1","2.15.0","2.12.1"]}],"database_specific":{"cwe_ids":["CWE-502","CWE-917"],"severity":"CRITICAL","github_reviewed":true}}`,
	`{"id":"GHSA-462w-v97r-4m45","summary":"Jinja2 sandbox escape via string formatting","details":"In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape.","aliases":["CVE-2019-10906","PYSEC-2019-217"],"modified":"2024-09-24T21:03:59.802687Z","published":"2019-04-10T14:30:24Z","severity":[{"type":"CVSS_V3","score":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N"}],"affected":[{"package":{"ecosystem":"PyPI","name":"jinja2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.10.1"}]}],"versions":["2.4","2.4.1","2.8","2.9","2.10"]}],"database_specific":{"cwe_ids":["CWE-693"],"severity":"HIGH","github_reviewed":true}}`,
	`{"id":"GHSA-hj2j-77xm-mc5v","summary":"Jinja2 sandbox escape via str.format","details":"In Pallets Jinja before 2.8.1, str.format allows a sandbox escape.","aliases":["CVE-2016-10745","PYSEC-2019-220"],"modified":"2024-09-24T21:03:59Z","published":"2019-04-10T14:30:13Z","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],"affected":[{"package":{"ecosystem":"PyPI","name":"jinja2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.8.1"}]}],"versions":["2.4","2.4.1","2.8"]}],"database_specific":{"severity":"HIGH"}}`,
	`{"id":"PYSEC-2014-8","details":"FileSystemBytecodeCache in Jinja2 2.7.2 does not properly create temporary directories, which allows local users to gain privileges.","aliases":["CVE-2014-1402"],"modified":"2021-07-05T00:01:21Z","published":"2014-05-19T14:55:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"jinja2"},"ranges":[{"type":"GIT","repo":"https://github.com/pallets/jinja","events":[{"introduced":"0"},{"fixed":"acb672b6a179567632e032f547582f30fa2f4aa7"}]},{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.7.2"}]}],"versions":["2.4","2.4.1","2.7"]}]}`,
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Versions []string `json:"versions"`
}

type osvIndexed struct {
	id       string
	raw      json.RawMessage
	affected []osvAffected
}

var osvIndex = func() []osvIndexed {
	out := make([]osvIndexed, 0, len(osvRecordsJSON))
	for _, s := range osvRecordsJSON {
		var v struct {
			ID       string        `json:"id"`
			Affected []osvAffected `json:"affected"`
		}
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			panic(err)
		}
		out = append(out, osvIndexed{id: v.ID, raw: json.RawMessage(s), affected: v.Affected})
	}
	return out
}()

type osvQueryBody struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token"`
}

// serveOSVQuery mirrors POST /v1/query: match by package (ecosystem + name),
// narrow by version when given, page with next_page_token. No match -> {}.
func serveOSVQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"code":12,"message":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var q osvQueryBody
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		http.Error(w, `{"code":3,"message":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}
	if q.Package.Name == "" {
		http.Error(w, `{"code":3,"message":"Invalid query."}`, http.StatusBadRequest)
		return
	}
	var matches []json.RawMessage
	for _, rec := range osvIndex {
		hit := false
		for _, a := range rec.affected {
			if !strings.EqualFold(a.Package.Ecosystem, q.Package.Ecosystem) || a.Package.Name != q.Package.Name {
				continue
			}
			if q.Version == "" {
				hit = true
			}
			for _, v := range a.Versions {
				if v == q.Version {
					hit = true
				}
			}
		}
		if hit {
			matches = append(matches, rec.raw)
		}
	}
	start, _ := strconv.Atoi(q.PageToken)
	if start < 0 || start > len(matches) {
		start = 0
	}
	end := start + OSVPageSize
	if end > len(matches) {
		end = len(matches)
	}
	resp := map[string]any{}
	if len(matches) > 0 {
		resp["vulns"] = matches[start:end]
	}
	if end < len(matches) {
		resp["next_page_token"] = strconv.Itoa(end)
	}
	writeJSON(w, resp)
}

// serveOSVVuln mirrors GET /v1/vulns/{id}: the record, or 404.
func serveOSVVuln(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, OSVPrefix+"/vulns/")
	for _, rec := range osvIndex {
		if rec.id == id {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(rec.raw)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"code":5,"message":"Vulnerability not found"}`))
}
