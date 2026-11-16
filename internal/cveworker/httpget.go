// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxBodyBytes bounds every response body the worker reads (the full CISA KEV
// feed is ~1.5 MB; NVD/EPSS/OSV pages are far smaller).
const maxBodyBytes = 64 << 20

// errNotFound is returned by doJSON for an HTTP 404 so callers that treat an
// unknown identifier as "no rows" (osv_vuln) can tell it apart from a failure.
type errNotFound struct{ msg string }

func (e *errNotFound) Error() string { return e.msg }

// doJSON performs one HTTP request (GET when body is nil, else POST with a
// JSON body) and returns the raw response body. Non-2xx statuses map to clear,
// source-prefixed errors (prefix is e.g. "kev", "epss", "osv"); a 404 is an
// *errNotFound.
func doJSON(ctx context.Context, hc *http.Client, prefix, method, rawURL string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return nil, fmt.Errorf("%s: build request: %w", prefix, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vgi-cve (+https://github.com/Query-farm/vgi-cve)")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: request failed: %w", prefix, err)
	}
	defer func() { _ = resp.Body.Close() }() // best-effort close; read errors are surfaced below

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: read response: %w", prefix, err)
	}
	snippet := strings.TrimSpace(string(data))
	if len(snippet) > 300 {
		snippet = snippet[:300] + "..."
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, &errNotFound{msg: fmt.Sprintf("%s: not found (HTTP 404): %s", prefix, snippet)}
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("%s: rate limited (HTTP 429); slow down and retry: %s", prefix, snippet)
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("%s: API error (HTTP %d): %s", prefix, resp.StatusCode, snippet)
	}
	return data, nil
}

// nextRows returns the next bounded slice of rows from a cursor and advances
// *offset past them; done=true once every row has been emitted. It is the
// generic form of CursorState.nextSlice used by the KEV/EPSS/OSV states (see
// the "WHY A CURSOR" note in functions.go: Offset must live in the gob state).
func nextRows[T any](rows []T, offset *int) (slice []T, done bool) {
	if *offset >= len(rows) {
		return nil, true
	}
	end := *offset + rowsPerTick
	if end > len(rows) {
		end = len(rows)
	}
	slice = rows[*offset:end]
	*offset = end
	return slice, false
}
