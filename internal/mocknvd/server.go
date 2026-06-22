// Copyright 2026 Query Farm LLC - https://query.farm

// Package mocknvd is an embedded HTTP server that serves canned NVD 2.0 CVE API
// JSON. It is shared by the Go unit tests (httptest) and the standalone
// cmd/mockserver binary used by the haybarn SQL E2E. It honors the same query
// parameters as the real NVD endpoint that this worker uses:
//
//	cveId=CVE-2021-44228          -> a Log4Shell-shaped record (10.0, CRITICAL)
//	cveId=CVE-2099-00000 (or any
//	  other unknown id)           -> HTTP 404
//	keywordSearch=...             -> a paginated 2-page response (3 records)
//	cpeName=...                   -> CVEs affecting a CPE
//
// Pagination is driven by resultsPerPage / startIndex exactly like NVD.
package mocknvd

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Handler returns an http.Handler serving the canned NVD 2.0 responses at the
// single path the worker calls. Mount it at /rest/json/cves/2.0.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/json/cves/2.0", serve)
	return mux
}

func serve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	switch {
	case q.Get("cveId") != "":
		serveCVEByID(w, q.Get("cveId"))
	case q.Get("keywordSearch") != "":
		servePaginated(w, keywordRecords, q)
	case q.Get("cpeName") != "":
		servePaginated(w, cpeRecords, q)
	default:
		http.Error(w, `{"message":"missing query parameter"}`, http.StatusBadRequest)
	}
}

func serveCVEByID(w http.ResponseWriter, id string) {
	rec, ok := byID[id]
	if !ok {
		// Mirror NVD: an unknown CVE ID yields a 404.
		http.Error(w, `{"message":"CVE not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, response{
		ResultsPerPage:  1,
		StartIndex:      0,
		TotalResults:    1,
		Vulnerabilities: []vuln{{CVE: rec}},
	})
}

// servePaginated returns one page of records honoring resultsPerPage /
// startIndex, so a client that pages correctly sees every record exactly once.
func servePaginated(w http.ResponseWriter, records []cveRecord, q map[string][]string) {
	get := func(k string) string {
		if v, ok := q[k]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}
	total := len(records)
	perPage, _ := strconv.Atoi(get("resultsPerPage"))
	if perPage <= 0 {
		perPage = total
	}
	start, _ := strconv.Atoi(get("startIndex"))
	if start < 0 {
		start = 0
	}

	var page []vuln
	for i := start; i < total && i < start+perPage; i++ {
		page = append(page, vuln{CVE: records[i]})
	}
	writeJSON(w, response{
		ResultsPerPage:  len(page),
		StartIndex:      start,
		TotalResults:    total,
		Vulnerabilities: page,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
