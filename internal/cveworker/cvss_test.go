// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"math"
	"testing"
)

func TestSeverityBands(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.0, "NONE"},
		{0.1, "LOW"},
		{3.9, "LOW"},
		{4.0, "MEDIUM"},
		{6.9, "MEDIUM"},
		{7.0, "HIGH"},
		{8.9, "HIGH"},
		{9.0, "CRITICAL"},
		{9.8, "CRITICAL"},
		{10.0, "CRITICAL"},
		{-1.0, "NONE"}, // clamped
		{11.0, "CRITICAL"},
	}
	for _, c := range cases {
		if got := Severity(c.score); got != c.want {
			t.Errorf("Severity(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestBaseScoreKnownVectors(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		// Canonical: the classic "worst case", Scope:Unchanged -> 9.8.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		// Log4Shell, Scope:Changed -> 10.0 (the changed-scope multiplier caps).
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		// Heartbleed: confidentiality only -> 7.5.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		// Scope:Changed with partial impact (CVE-2021-45046 shape) -> 9.0.
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0},
		// All None impact -> 0.0 base score.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		// Local, high privileges, requires UI (a low-severity desktop bug) -> 5.5.
		{"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.5},
		// Version 3.0 prefix is accepted.
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		// No version prefix is accepted.
		{"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	}
	for _, c := range cases {
		got, err := BaseScore(c.vector)
		if err != nil {
			t.Errorf("BaseScore(%q) error: %v", c.vector, err)
			continue
		}
		if math.Abs(got-c.want) > 1e-9 {
			t.Errorf("BaseScore(%q) = %v, want %v", c.vector, got, c.want)
		}
	}
}

func TestBaseScoreErrors(t *testing.T) {
	bad := []string{
		"",                                    // empty
		"CVSS:2.0/AV:N",                       // unsupported version
		"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",     // missing A
		"AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",     // missing S (Scope)
		"AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // bad AV value
		"AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H", // bad Scope value
		"AV:N/AC:L/PR:Z/UI:N/S:U/C:H/I:H/A:H", // bad PR value
		"not-a-vector",                        // malformed token
	}
	for _, v := range bad {
		if _, err := BaseScore(v); err == nil {
			t.Errorf("BaseScore(%q) expected error, got nil", v)
		}
	}
}
