// Copyright 2026 Query Farm LLC - https://query.farm

package mocknvd

import "net/http"

// KEVPath is where the mock serves the CISA KEV JSON feed (the same path as
// the real feed on www.cisa.gov).
const KEVPath = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// kevFeedJSON is a 4-entry, CISA-shaped KEV catalog. Heartbleed carries empty
// notes and no CWEs, exercising the NULL notes / empty cwes paths.
const kevFeedJSON = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.11.13",
  "dateReleased": "2026-11-13T20:24:18.3008Z",
  "count": 4,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "dateAdded": "2021-12-10",
      "shortDescription": "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.",
      "requiredAction": "For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known",
      "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      "cwes": ["CWE-20", "CWE-400", "CWE-502"]
    },
    {
      "cveID": "CVE-2022-22965",
      "vendorProject": "VMware",
      "product": "Spring Framework",
      "vulnerabilityName": "Spring Framework JDK 9+ Remote Code Execution Vulnerability",
      "dateAdded": "2022-04-04",
      "shortDescription": "Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2022-04-25",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "https://tanzu.vmware.com/security/cve-2022-22965",
      "cwes": ["CWE-94"]
    },
    {
      "cveID": "CVE-2021-45046",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 Deserialization of Untrusted Data Vulnerability",
      "dateAdded": "2023-05-01",
      "shortDescription": "Apache Log4j2 contains a deserialization of untrusted data vulnerability due to the incomplete fix of CVE-2021-44228.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2023-05-22",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "https://logging.apache.org/log4j/2.x/security.html",
      "cwes": ["CWE-917"]
    },
    {
      "cveID": "CVE-2014-0160",
      "vendorProject": "OpenSSL",
      "product": "OpenSSL",
      "vulnerabilityName": "OpenSSL Information Disclosure Vulnerability",
      "dateAdded": "2022-05-04",
      "shortDescription": "The TLS and DTLS implementations in OpenSSL do not properly handle Heartbeat Extension packets, allowing remote attackers to obtain sensitive information.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2022-05-25",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": ""
    }
  ]
}`

func serveKEV(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(kevFeedJSON))
}
