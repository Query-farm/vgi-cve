// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

// Shared helpers for the per-object discovery/description metadata that the
// vgi-lint strict profile expects on EVERY function and table.
//
// Each function/table surfaces these in its FunctionMetadata.Tags:
//   - vgi.title     (VGI124) — human-friendly display name
//   - vgi.doc_llm   (VGI112) — Markdown narrative aimed at LLMs/agents
//   - vgi.doc_md    (VGI113) — Markdown narrative for human docs
//   - vgi.keywords  (VGI126/VGI138) — JSON array of search terms/synonyms
//
// Per-object vgi.source_url is intentionally NOT set (VGI139): source_url
// belongs on the catalog object only; the per-object copies are redundant.

// objectTags builds the four standard per-object discovery/description tags.
// keywords must be a JSON array of strings (e.g. `["a","b"]`) per VGI138.
func objectTags(title, descriptionLLM, descriptionMD, keywords string) map[string]string {
	return map[string]string{
		"vgi.title":    title,
		"vgi.doc_llm":  descriptionLLM,
		"vgi.doc_md":   descriptionMD,
		"vgi.keywords": keywords,
	}
}

// withColumnsMD returns objectTags plus a vgi.result_columns_md table-shape doc.
func withColumnsMD(title, descriptionLLM, descriptionMD, keywords, columnsMD string) map[string]string {
	t := objectTags(title, descriptionLLM, descriptionMD, keywords)
	t["vgi.result_columns_md"] = columnsMD
	return t
}
