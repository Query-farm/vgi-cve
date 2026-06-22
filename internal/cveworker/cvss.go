// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"fmt"
	"math"
	"strings"
)

// This file implements pure, offline CVSS v3.x math: no network, fully
// deterministic, and the easiest part of the worker to test. Two surfaces:
//
//   - Severity(score): map a numeric base score to a CVSS v3 qualitative band.
//   - BaseScore(vector): compute a CVSS v3.1 Base Score from a vector string.
//
// The base-score equation follows the official CVSS v3.1 specification
// (https://www.first.org/cvss/v3.1/specification-document, section 7.1).

// Severity maps a CVSS v3 base score to its qualitative rating band.
//
//	0.0        -> NONE
//	0.1 – 3.9  -> LOW
//	4.0 – 6.9  -> MEDIUM
//	7.0 – 8.9  -> HIGH
//	9.0 – 10.0 -> CRITICAL
//
// Out-of-range scores are clamped to the nearest band.
func Severity(score float64) string {
	switch {
	case score <= 0.0:
		return "NONE"
	case score < 4.0:
		return "LOW"
	case score < 7.0:
		return "MEDIUM"
	case score < 9.0:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// Metric weight tables from the CVSS v3.1 specification (section 7.4).

var attackVectorWeights = map[string]float64{
	"N": 0.85, // Network
	"A": 0.62, // Adjacent
	"L": 0.55, // Local
	"P": 0.20, // Physical
}

var attackComplexityWeights = map[string]float64{
	"L": 0.77, // Low
	"H": 0.44, // High
}

// Privileges Required has two columns; the value depends on Scope (Changed
// raises the weight for Low/High because crossing a privilege boundary is
// worth more when the impact escapes the vulnerable component's scope).
var privilegesRequiredWeights = map[string]struct{ Unchanged, Changed float64 }{
	"N": {0.85, 0.85}, // None
	"L": {0.62, 0.68}, // Low
	"H": {0.27, 0.50}, // High
}

var userInteractionWeights = map[string]float64{
	"N": 0.85, // None
	"R": 0.62, // Required
}

// Confidentiality / Integrity / Availability impacts share one table.
var ciaWeights = map[string]float64{
	"H": 0.56, // High
	"L": 0.22, // Low
	"N": 0.00, // None
}

// BaseScore computes the CVSS v3.1 Base Score from a vector string such as
//
//	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H   (-> 9.8)
//
// Only the Base metric group is required; any Temporal/Environmental metrics
// present in the vector are ignored. The "CVSS:3.0"/"CVSS:3.1" prefix is
// optional and accepted. Returns an error if a required metric is missing or a
// metric value is not recognized.
func BaseScore(vector string) (float64, error) {
	metrics, err := parseVector(vector)
	if err != nil {
		return 0, err
	}

	av, err := lookup(metrics, "AV", attackVectorWeights)
	if err != nil {
		return 0, err
	}
	ac, err := lookup(metrics, "AC", attackComplexityWeights)
	if err != nil {
		return 0, err
	}
	ui, err := lookup(metrics, "UI", userInteractionWeights)
	if err != nil {
		return 0, err
	}
	c, err := lookup(metrics, "C", ciaWeights)
	if err != nil {
		return 0, err
	}
	i, err := lookup(metrics, "I", ciaWeights)
	if err != nil {
		return 0, err
	}
	a, err := lookup(metrics, "A", ciaWeights)
	if err != nil {
		return 0, err
	}

	scopeVal, ok := metrics["S"]
	if !ok {
		return 0, fmt.Errorf("cvss: vector missing required metric S (Scope)")
	}
	var scopeChanged bool
	switch scopeVal {
	case "U":
		scopeChanged = false
	case "C":
		scopeChanged = true
	default:
		return 0, fmt.Errorf("cvss: invalid value %q for metric S (Scope)", scopeVal)
	}

	prVal, ok := metrics["PR"]
	if !ok {
		return 0, fmt.Errorf("cvss: vector missing required metric PR (Privileges Required)")
	}
	prWeights, ok := privilegesRequiredWeights[prVal]
	if !ok {
		return 0, fmt.Errorf("cvss: invalid value %q for metric PR (Privileges Required)", prVal)
	}
	pr := prWeights.Unchanged
	if scopeChanged {
		pr = prWeights.Changed
	}

	// ISCBase = 1 - [ (1-C) * (1-I) * (1-A) ]
	iscBase := 1 - (1-c)*(1-i)*(1-a)

	// Impact sub-score depends on Scope.
	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}

	// Exploitability = 8.22 * AV * AC * PR * UI
	exploitability := 8.22 * av * ac * pr * ui

	// If the impact sub-score is 0, the base score is 0.
	if impact <= 0 {
		return 0.0, nil
	}

	var base float64
	if scopeChanged {
		base = roundUp1(math.Min(1.08*(impact+exploitability), 10))
	} else {
		base = roundUp1(math.Min(impact+exploitability, 10))
	}
	return base, nil
}

// parseVector splits a CVSS vector string into a metric->value map. An optional
// leading "CVSS:3.0" / "CVSS:3.1" prefix is consumed. Metric tokens are
// "KEY:VALUE" separated by '/'.
func parseVector(vector string) (map[string]string, error) {
	v := strings.TrimSpace(vector)
	if v == "" {
		return nil, fmt.Errorf("cvss: empty vector string")
	}
	parts := strings.Split(v, "/")
	metrics := make(map[string]string, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("cvss: malformed metric token %q in vector", p)
		}
		key := strings.ToUpper(kv[0])
		val := strings.ToUpper(kv[1])
		// Consume the version prefix; reject any non-3.x version.
		if key == "CVSS" {
			if val != "3.0" && val != "3.1" {
				return nil, fmt.Errorf("cvss: unsupported version %q (only 3.0/3.1)", kv[1])
			}
			continue
		}
		metrics[key] = val
	}
	if len(metrics) == 0 {
		return nil, fmt.Errorf("cvss: no metrics found in vector %q", vector)
	}
	return metrics, nil
}

// lookup resolves a required metric's weight, returning a clear error when the
// metric is absent or carries an unrecognized value.
func lookup(metrics map[string]string, key string, table map[string]float64) (float64, error) {
	val, ok := metrics[key]
	if !ok {
		return 0, fmt.Errorf("cvss: vector missing required metric %s", key)
	}
	w, ok := table[val]
	if !ok {
		return 0, fmt.Errorf("cvss: invalid value %q for metric %s", val, key)
	}
	return w, nil
}

// roundUp1 implements the CVSS v3.1 "Roundup" function: the smallest number,
// to one decimal place, that is >= the input. The spec defines it on integer
// arithmetic at 1/100000 precision to avoid binary floating-point drift.
func roundUp1(x float64) float64 {
	intInput := int64(math.Round(x * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000
	}
	return float64(intInput/10000+1) / 10
}
