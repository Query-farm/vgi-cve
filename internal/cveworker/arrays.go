// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"time"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// stringListType is the Arrow type behind a DuckDB VARCHAR[] column.
var stringListType = arrow.ListOf(arrow.BinaryTypes.String)

// buildNullableString builds a VARCHAR column where an empty string from fn
// becomes SQL NULL (used for optional source fields such as a missing CVSS
// vector or KEV notes).
func buildNullableString(n int, fn func(i int) string) arrow.Array {
	b := array.NewStringBuilder(memory.NewGoAllocator())
	defer b.Release()
	b.Reserve(n)
	for i := 0; i < n; i++ {
		if v := fn(i); v == "" {
			b.AppendNull()
		} else {
			b.Append(v)
		}
	}
	return b.NewArray()
}

// buildNullableDate builds a DATE (Arrow date32) column from YYYY-MM-DD
// strings; an empty or unparseable value becomes SQL NULL.
func buildNullableDate(n int, fn func(i int) string) arrow.Array {
	b := array.NewDate32Builder(memory.NewGoAllocator())
	defer b.Release()
	b.Reserve(n)
	for i := 0; i < n; i++ {
		t, ok := parseDate(fn(i))
		if !ok {
			b.AppendNull()
			continue
		}
		b.Append(arrow.Date32FromTime(t))
	}
	return b.NewArray()
}

// parseDate parses the leading YYYY-MM-DD of s (tolerating a trailing time
// component) as a UTC calendar date.
func parseDate(s string) (time.Time, bool) {
	if len(s) < 10 {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", s[:10])
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// buildStringList builds a non-NULL VARCHAR[] column (an empty source slice
// becomes an empty list, not NULL).
func buildStringList(n int, fn func(i int) []string) arrow.Array {
	b := array.NewListBuilder(memory.NewGoAllocator(), arrow.BinaryTypes.String)
	defer b.Release()
	vb := b.ValueBuilder().(*array.StringBuilder)
	for i := 0; i < n; i++ {
		b.Append(true)
		for _, v := range fn(i) {
			vb.Append(v)
		}
	}
	return b.NewArray()
}
