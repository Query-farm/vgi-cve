// Copyright 2026 Query Farm LLC - https://query.farm

package mocknvd

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// EPSSPath is where the mock serves the FIRST EPSS API (same path as
// api.first.org).
const EPSSPath = "/data/v1/epss"

// EPSSServerMaxLimit caps the page size like a real API would, so a client
// that does not follow offset/total pagination loses rows in the tests.
const EPSSServerMaxLimit = 100

// epssCurrentDate is the "latest" score date the mock reports.
const epssCurrentDate = "2026-11-14"

type epssScore struct{ epss, percentile string }

var epssScores = map[string]epssScore{
	"CVE-2021-44228": {"0.943580000", "0.999610000"},
	"CVE-2021-45046": {"0.941340000", "0.999150000"},
	"CVE-2022-22965": {"0.944670000", "0.999770000"},
	"CVE-2014-0160":  {"0.944200000", "0.999690000"},
}

// epssHistorical overrides scores for a (date, cve) pair.
var epssHistorical = map[string]epssScore{
	"2023-03-01/CVE-2021-44228": {"0.970950000", "0.999980000"},
}

type epssDatum struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// serveEPSS mirrors api.first.org/data/v1/epss: cve= comma list (max 2000
// chars, else 400), optional date=, limit/offset paging, total count. Any id
// starting CVE-1999- gets a synthetic low score (for batching tests); unknown
// ids are omitted, as the real API does.
func serveEPSS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cveParam := q.Get("cve")
	if len(cveParam) > 2000 {
		http.Error(w, `{"status":"error","message":"cve parameter exceeds 2000 characters"}`, http.StatusBadRequest)
		return
	}
	date := q.Get("date")
	if date == "" {
		date = epssCurrentDate
	}
	var all []epssDatum
	seen := map[string]bool{}
	for _, id := range strings.Split(cveParam, ",") {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		s, ok := epssHistorical[date+"/"+id]
		if !ok {
			s, ok = epssScores[id]
		}
		if !ok && strings.HasPrefix(id, "CVE-1999-") {
			s, ok = epssScore{"0.000420000", "0.050000000"}, true
		}
		if ok {
			all = append(all, epssDatum{CVE: id, EPSS: s.epss, Percentile: s.percentile, Date: date})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CVE < all[j].CVE })

	limit, err := strconv.Atoi(q.Get("limit"))
	if err != nil || limit <= 0 {
		limit = 100
	}
	if limit > EPSSServerMaxLimit {
		limit = EPSSServerMaxLimit
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	page := []epssDatum{}
	for i := offset; i < len(all) && i < offset+limit; i++ {
		page = append(page, all[i])
	}
	writeJSON(w, map[string]any{
		"status":      "OK",
		"status-code": 200,
		"version":     "1.0",
		"access":      "public",
		"total":       len(all),
		"offset":      offset,
		"limit":       limit,
		"data":        page,
	})
}
