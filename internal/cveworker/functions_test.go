// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"net/http/httptest"
	"testing"

	"github.com/Query-farm/vgi-cve/internal/mocknvd"
	"github.com/Query-farm/vgi-go/vgi"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// strCol builds a 1-row string array (optionally NULL) for a positional arg.
func strCol(t *testing.T, v string, null bool) arrow.Array {
	t.Helper()
	b := array.NewStringBuilder(memory.DefaultAllocator)
	defer b.Release()
	if null {
		b.AppendNull()
	} else {
		b.Append(v)
	}
	return b.NewArray()
}

// argsWithBaseURL builds *vgi.Arguments with a single positional plus the
// base_url named option pointing at the in-process mock NVD server.
func argsWithBaseURL(pos arrow.Array, baseURL string) *vgi.Arguments {
	return &vgi.Arguments{
		Positional: []arrow.Array{pos},
		Named:      map[string]arrow.Array{"base_url": stringScalar(baseURL)},
	}
}

func stringScalar(v string) arrow.Array {
	b := array.NewStringBuilder(memory.DefaultAllocator)
	defer b.Release()
	b.Append(v)
	return b.NewArray()
}

func mockBaseURL(t *testing.T) (string, func()) {
	t.Helper()
	srv := httptest.NewServer(mocknvd.Handler())
	return srv.URL + "/rest/json/cves/2.0", srv.Close
}

func TestCVEFunctionNewState(t *testing.T) {
	base, cleanup := mockBaseURL(t)
	defer cleanup()

	f := &CVEFunction{}
	st, err := f.NewState(&vgi.ProcessParams{
		Args: argsWithBaseURL(strCol(t, "CVE-2021-44228", false), base),
	})
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	if len(st.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(st.Rows))
	}
	if st.Rows[0].ID != "CVE-2021-44228" || st.Rows[0].SeverityStr != "CRITICAL" {
		t.Errorf("unexpected row: %+v", st.Rows[0])
	}
	if st.Done {
		t.Error("state should not be done before Process")
	}
}

func TestCVEFunctionNullArgNoRows(t *testing.T) {
	base, cleanup := mockBaseURL(t)
	defer cleanup()

	f := &CVEFunction{}
	st, err := f.NewState(&vgi.ProcessParams{
		Args: argsWithBaseURL(strCol(t, "", true), base),
	})
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	if len(st.Rows) != 0 {
		t.Errorf("NULL arg should yield no rows, got %d", len(st.Rows))
	}
}

func TestCVEFunctionUnknownErrors(t *testing.T) {
	base, cleanup := mockBaseURL(t)
	defer cleanup()

	f := &CVEFunction{}
	_, err := f.NewState(&vgi.ProcessParams{
		Args: argsWithBaseURL(strCol(t, "CVE-0000-99999", false), base),
	})
	if err == nil {
		t.Error("expected error for unknown CVE (mock 404), got nil")
	}
}

func TestCVESearchFunctionNewState(t *testing.T) {
	base, cleanup := mockBaseURL(t)
	defer cleanup()

	f := &CVESearchFunction{}
	st, err := f.NewState(&vgi.ProcessParams{
		Args: argsWithBaseURL(strCol(t, "log4j", false), base),
	})
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	if len(st.Rows) != 3 {
		t.Fatalf("expected 3 search rows, got %d", len(st.Rows))
	}
}

func TestCPECVEsFunctionNewState(t *testing.T) {
	base, cleanup := mockBaseURL(t)
	defer cleanup()

	f := &CPECVEsFunction{}
	st, err := f.NewState(&vgi.ProcessParams{
		Args: argsWithBaseURL(strCol(t, "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", false), base),
	})
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	if len(st.Rows) != 3 {
		t.Fatalf("expected 3 CPE rows, got %d", len(st.Rows))
	}
}

func TestRegisterDoesNotPanic(t *testing.T) {
	// Registration triggers the SDK's gob-encodability check on table-function
	// state; this guards against re-introducing a non-encodable state field.
	w := vgi.NewWorker(vgi.WithCatalogName(CatalogName))
	Register(w)
}
