// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the real NVD 2.0 CVE API endpoint. Every table function
// accepts a base_url named option so the E2E suite can redirect requests at the
// local mock server.
const DefaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// MaxResults bounds the total number of rows the search/CPE functions will
// fetch across pages, so an over-broad query cannot run forever.
const MaxResults = 100

// resultsPerPage is the page size requested from the NVD API. NVD permits up to
// 2000; we use a modest page so the bounded fetch makes few round trips.
const resultsPerPage = 50

// defaultTimeout bounds every HTTP call (per request, not per page) so a slow
// or unreachable endpoint fails fast rather than hanging DuckDB.
const defaultTimeout = 30 * time.Second

// Client talks to an NVD 2.0-compatible CVE API.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// NewClient builds a Client. An empty baseURL falls back to the real NVD
// endpoint; an empty apiKey means unauthenticated (subject to NVD's stricter
// public rate limit).
func NewClient(baseURL, apiKey string) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: defaultTimeout},
	}
}

// CVERow is the flattened, SQL-friendly projection of a single NVD CVE record.
// A nil pointer field means the source record had no value (e.g. a CVE with no
// CVSS metrics yields a nil Score, surfaced as SQL NULL).
type CVERow struct {
	ID           string
	Description  string
	Score        *float64
	SeverityStr  string
	Vector       string
	Published    string
	LastModified string
	CWE          string
}

// ---------------------------------------------------------------------------
// NVD 2.0 JSON shapes (only the fields we project).
// ---------------------------------------------------------------------------

type nvdResponse struct {
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
	TotalResults    int                `json:"totalResults"`
	Vulnerabilities []nvdVulnContainer `json:"vulnerabilities"`
}

type nvdVulnContainer struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string          `json:"id"`
	Published    string          `json:"published"`
	LastModified string          `json:"lastModified"`
	Descriptions []nvdLangString `json:"descriptions"`
	Metrics      nvdMetrics      `json:"metrics"`
	Weaknesses   []nvdWeakness   `json:"weaknesses"`
}

type nvdLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSMetric   `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric   `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetricV2 `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSMetricV2 struct {
	CVSSData     nvdCVSSData `json:"cvssData"`
	BaseSeverity string      `json:"baseSeverity"`
}

type nvdCVSSData struct {
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdWeakness struct {
	Description []nvdLangString `json:"description"`
}

// projectCVE flattens an NVD CVE record into a CVERow.
func projectCVE(c nvdCVE) CVERow {
	row := CVERow{
		ID:           c.ID,
		Published:    c.Published,
		LastModified: c.LastModified,
	}
	row.Description = englishOr(c.Descriptions)
	row.CWE = firstCWE(c.Weaknesses)

	// Prefer CVSS v3.1, then v3.0, then v2. A record with no metrics leaves
	// Score nil (SQL NULL) and the severity/vector empty.
	switch {
	case len(c.Metrics.CVSSMetricV31) > 0:
		applyCVSS(&row, c.Metrics.CVSSMetricV31[0].CVSSData)
	case len(c.Metrics.CVSSMetricV30) > 0:
		applyCVSS(&row, c.Metrics.CVSSMetricV30[0].CVSSData)
	case len(c.Metrics.CVSSMetricV2) > 0:
		m := c.Metrics.CVSSMetricV2[0]
		applyCVSS(&row, m.CVSSData)
		// CVSS v2 carries severity on the metric, not in cvssData.
		if row.SeverityStr == "" {
			row.SeverityStr = strings.ToUpper(m.BaseSeverity)
		}
	}
	return row
}

func applyCVSS(row *CVERow, d nvdCVSSData) {
	score := d.BaseScore
	row.Score = &score
	row.Vector = d.VectorString
	if d.BaseSeverity != "" {
		row.SeverityStr = strings.ToUpper(d.BaseSeverity)
	} else {
		row.SeverityStr = Severity(score)
	}
}

func englishOr(ds []nvdLangString) string {
	for _, d := range ds {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(ds) > 0 {
		return ds[0].Value
	}
	return ""
}

func firstCWE(ws []nvdWeakness) string {
	for _, w := range ws {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				return d.Value
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

// FetchCVE retrieves a single CVE by ID. Returns (nil, nil) when the API
// reports zero matches (e.g. an unknown but well-formed ID with 200/empty), and
// an error for a 404 or any other failure.
func (c *Client) FetchCVE(ctx context.Context, cveID string) (*CVERow, error) {
	q := url.Values{}
	q.Set("cveId", cveID)
	resp, err := c.get(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(resp.Vulnerabilities) == 0 {
		return nil, nil
	}
	row := projectCVE(resp.Vulnerabilities[0].CVE)
	return &row, nil
}

// SearchKeyword runs a keyword search, paginating until MaxResults rows are
// collected or the API is exhausted.
func (c *Client) SearchKeyword(ctx context.Context, keyword string) ([]CVERow, error) {
	return c.paginate(ctx, func(q url.Values) { q.Set("keywordSearch", keyword) })
}

// CVEsForCPE returns CVEs associated with a CPE name, paginated and bounded by
// MaxResults.
func (c *Client) CVEsForCPE(ctx context.Context, cpe string) ([]CVERow, error) {
	return c.paginate(ctx, func(q url.Values) { q.Set("cpeName", cpe) })
}

// paginate walks pages of results, applying setParams to seed the query-specific
// parameters, until MaxResults rows are gathered or no more results remain.
func (c *Client) paginate(ctx context.Context, setParams func(url.Values)) ([]CVERow, error) {
	var rows []CVERow
	startIndex := 0
	for {
		q := url.Values{}
		setParams(q)
		q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
		q.Set("startIndex", strconv.Itoa(startIndex))

		resp, err := c.get(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, v := range resp.Vulnerabilities {
			rows = append(rows, projectCVE(v.CVE))
			if len(rows) >= MaxResults {
				return rows, nil
			}
		}
		startIndex += len(resp.Vulnerabilities)
		// Stop when the server returned an empty page or we've consumed every
		// reported result.
		if len(resp.Vulnerabilities) == 0 || startIndex >= resp.TotalResults {
			break
		}
	}
	return rows, nil
}

// get performs one HTTP GET against the configured base URL with the given
// query parameters, decoding the NVD 2.0 envelope. It maps non-200 statuses
// (including 404 and 429 rate-limiting) and JSON decode failures to clear
// errors suitable for surfacing in DuckDB.
func (c *Client) get(ctx context.Context, q url.Values) (*nvdResponse, error) {
	full := c.BaseURL
	if enc := q.Encode(); enc != "" {
		sep := "?"
		if strings.Contains(full, "?") {
			sep = "&"
		}
		full = full + sep + enc
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, fmt.Errorf("nvd: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("nvd: read response: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("nvd: not found (HTTP 404): %s", strings.TrimSpace(string(body)))
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("nvd: rate limited (HTTP 429); set an api_key or slow down: %s", strings.TrimSpace(string(body)))
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("nvd: API error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out nvdResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("nvd: decode JSON response: %w", err)
	}
	return &out, nil
}
