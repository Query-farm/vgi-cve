// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"bytes"
	"encoding/gob"
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
	if st.Offset != 0 {
		t.Errorf("cursor should start at offset 0 before Process, got %d", st.Offset)
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

// TestCursorSurvivesContinuation simulates the HTTP transport's stateless
// continuation: the producer state is gob round-tripped between every Process
// tick (exactly what the framework does when it snapshots the state into a
// continuation token and resumes from it). It asserts the cursor (a) advances
// across the boundary, (b) emits every row exactly once, and (c) terminates.
//
// This is the fast regression guard for the HTTP infinite-loop bug: a state that
// only carried a post-Emit `Done bool` would observe the pre-Emit snapshot on
// each resume, re-emit row 0 forever, and never finish. The explicit Offset
// cursor makes the snapshot authoritative, so this terminates with len(Rows)
// rows total.
func TestCursorSurvivesContinuation(t *testing.T) {
	rows := make([]CVERow, 150) // > rowsPerTick, forcing several continuations
	for i := range rows {
		rows[i].ID = "CVE-X"
	}

	// emitted counts how many rows each simulated tick produced.
	type tick struct{ n int }
	var ticks []tick
	state := &cveSearchState{CursorState: CursorState{Rows: rows}}

	for i := 0; i < len(rows)+10; i++ { // generous upper bound; must terminate sooner
		slice, done := state.nextSlice()
		if done {
			ticks = append(ticks, tick{n: -1}) // -1 marks the Finish tick
			break
		}
		ticks = append(ticks, tick{n: len(slice)})

		// Simulate the HTTP continuation boundary: gob-encode the live state and
		// decode it back, exactly like the framework's token round-trip. If the
		// cursor did not serialize, Offset would reset and the loop would not end.
		encoded, err := gobRoundTrip(state)
		if err != nil {
			t.Fatalf("gob round-trip tick %d: %v", i, err)
		}
		state = encoded
	}

	total := 0
	finished := false
	for _, tk := range ticks {
		if tk.n == -1 {
			finished = true
			break
		}
		total += tk.n
	}
	if !finished {
		t.Fatalf("cursor never reached Finish() — emitted %d rows in %d ticks (infinite-loop regression)", total, len(ticks))
	}
	if total != len(rows) {
		t.Errorf("emitted %d rows across continuations, want %d (rows duplicated or dropped)", total, len(rows))
	}
}

// gobRoundTrip encodes the cursor portion of a state through gob and decodes it
// back, mirroring how the HTTP transport serializes producer state into a
// continuation token. We round-trip the embedded CursorState (the part the
// framework's user-state snapshot carries) and rebuild the typed state.
func gobRoundTrip(s *cveSearchState) (*cveSearchState, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(s.CursorState); err != nil {
		return nil, err
	}
	var cs CursorState
	if err := gob.NewDecoder(&buf).Decode(&cs); err != nil {
		return nil, err
	}
	return &cveSearchState{CursorState: cs}, nil
}
