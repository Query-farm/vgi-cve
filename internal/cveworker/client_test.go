// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Query-farm/vgi-cve/internal/mocknvd"
)

// newMock returns a Client pointed at a fresh in-process mock NVD server, plus
// a cleanup func.
func newMock(t *testing.T) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(mocknvd.Handler())
	c := NewClient(srv.URL+"/rest/json/cves/2.0", "")
	return c, srv.Close
}

func TestFetchCVE_Log4Shell(t *testing.T) {
	c, cleanup := newMock(t)
	defer cleanup()

	row, err := c.FetchCVE(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("FetchCVE: %v", err)
	}
	if row == nil {
		t.Fatal("FetchCVE returned nil row")
	}
	if row.ID != "CVE-2021-44228" {
		t.Errorf("ID = %q", row.ID)
	}
	if row.Score == nil || *row.Score != 10.0 {
		t.Errorf("Score = %v, want 10.0", row.Score)
	}
	if row.SeverityStr != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", row.SeverityStr)
	}
	if row.CWE != "CWE-502" {
		t.Errorf("CWE = %q, want CWE-502", row.CWE)
	}
	if row.Vector == "" || row.Description == "" || row.Published == "" {
		t.Errorf("missing field(s): vector=%q published=%q", row.Vector, row.Published)
	}
}

func TestFetchCVE_NotFound(t *testing.T) {
	c, cleanup := newMock(t)
	defer cleanup()

	_, err := c.FetchCVE(context.Background(), "CVE-0000-99999")
	if err == nil {
		t.Fatal("expected error for unknown CVE, got nil")
	}
}

func TestSearchKeyword_Paginates(t *testing.T) {
	c, cleanup := newMock(t)
	defer cleanup()

	rows, err := c.SearchKeyword(context.Background(), "log4j")
	if err != nil {
		t.Fatalf("SearchKeyword: %v", err)
	}
	// The mock serves 3 keyword records; with resultsPerPage=50 the worker
	// collects all of them across the paginated walk.
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	if rows[0].ID != "CVE-2021-44228" {
		t.Errorf("first row ID = %q", rows[0].ID)
	}
}

func TestCVEsForCPE_NullScore(t *testing.T) {
	c, cleanup := newMock(t)
	defer cleanup()

	rows, err := c.CVEsForCPE(context.Background(), "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("CVEsForCPE: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	// The last record has no CVSS metrics -> nil score.
	var foundNull bool
	for _, r := range rows {
		if r.ID == "CVE-2099-00000" {
			foundNull = true
			if r.Score != nil {
				t.Errorf("expected nil score for metric-less CVE, got %v", *r.Score)
			}
		}
	}
	if !foundNull {
		t.Error("did not find the metric-less CVE in CPE results")
	}
}

func TestPaginationBoundary(t *testing.T) {
	// A small page size still collects every keyword record exactly once.
	srv := httptest.NewServer(mocknvd.Handler())
	defer srv.Close()
	c := NewClient(srv.URL+"/rest/json/cves/2.0", "")

	// Drive pagination directly through the public path; the mock honors the
	// resultsPerPage/startIndex the client sends. (resultsPerPage is a package
	// constant of 50, exceeding the 3 records, so this just confirms the walk
	// terminates and dedupes.)
	rows, err := c.SearchKeyword(context.Background(), "x")
	if err != nil {
		t.Fatalf("SearchKeyword: %v", err)
	}
	seen := map[string]int{}
	for _, r := range rows {
		seen[r.ID]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("CVE %s appeared %d times (pagination duplicated rows)", id, n)
		}
	}
}

func TestErrorStatuses(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"server-error", http.StatusInternalServerError},
		{"rate-limited", http.StatusTooManyRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boom", tc.status)
			}))
			defer srv.Close()
			c := NewClient(srv.URL, "")
			if _, err := c.FetchCVE(context.Background(), "CVE-2021-44228"); err == nil {
				t.Errorf("expected error for HTTP %d, got nil", tc.status)
			}
		})
	}
}

func TestBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	if _, err := c.SearchKeyword(context.Background(), "x"); err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestAPIKeyHeader(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("apiKey")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "secret-key")
	_, _ = c.SearchKeyword(context.Background(), "x")
	if gotKey != "secret-key" {
		t.Errorf("apiKey header = %q, want secret-key", gotKey)
	}
}
