// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import "encoding/json"

// Shared helpers for the per-object discovery/description metadata that the
// vgi-lint strict profile expects on EVERY function and table.
//
// Each function/table surfaces these in its FunctionMetadata.Tags:
//   - vgi.title     (VGI124) — human-friendly display name
//   - vgi.doc_llm   (VGI112) — Markdown narrative aimed at LLMs/agents
//   - vgi.doc_md    (VGI113) — Markdown narrative for human docs
//   - vgi.keywords  (VGI126/VGI138) — JSON array of search terms/synonyms
//   - vgi.category  (VGI409/VGI413) — one of the schema's vgi.categories entries
//
// Per-object vgi.source_url is intentionally NOT set (VGI139): source_url
// belongs on the catalog object only; the per-object copies are redundant.

// resultColumn describes one column of a table function's static result schema.
// A slice of these is serialized into the structured vgi.result_columns_schema
// tag — the replacement for the retired free-form vgi.result_columns_md.
type resultColumn struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

// objectTags builds the standard per-object discovery/description tags.
// keywords must be a JSON array of strings (e.g. `["a","b"]`) per VGI138.
// category (VGI409/VGI413) must name one of the schema's vgi.categories entries.
func objectTags(title, descriptionLLM, descriptionMD, keywords, category string) map[string]string {
	return map[string]string{
		"vgi.title":    title,
		"vgi.doc_llm":  descriptionLLM,
		"vgi.doc_md":   descriptionMD,
		"vgi.keywords": keywords,
		"vgi.category": category,
	}
}

// withResultSchema returns objectTags plus the structured vgi.result_columns_schema
// tag: a JSON array of {name,type,description} declaring the table function's
// static result shape. This replaces the retired free-form vgi.result_columns_md
// (VGI414) and is validated by VGI307/321/322/323 (and, under --execute, VGI910
// against what the function actually returns), so the column names and DuckDB
// types here MUST match each table function's Arrow output schema exactly.
func withResultSchema(title, descriptionLLM, descriptionMD, keywords, category string, columns []resultColumn) map[string]string {
	t := objectTags(title, descriptionLLM, descriptionMD, keywords, category)
	b, err := json.Marshal(columns)
	if err != nil {
		// The input is a static literal; a marshal error is a programming bug.
		panic(err)
	}
	t["vgi.result_columns_schema"] = string(b)
	return t
}
