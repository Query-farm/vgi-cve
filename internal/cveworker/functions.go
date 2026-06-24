// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"context"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-rpc-go/vgirpc"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// Compile-time checks: the offline scalars implement vgi.ScalarFunction
// directly (no typed wrapper needed), so RegisterScalar can take them as-is.
var (
	_ vgi.ScalarFunction = (*CVSSSeverityFunction)(nil)
	_ vgi.ScalarFunction = (*CVSSBaseScoreFunction)(nil)
)

// CatalogName is the VGI catalog name advertised by this worker.
const CatalogName = "cve"

// IMPORTANT (gob-state gotcha): table-function state is gob-encoded by the SDK
// between NewState and Process (it may cross a process boundary). State structs
// must therefore hold only EXPORTED, gob-encodable fields — no arrow.Record, no
// interfaces, channels, funcs, or unexported fields. Each table function fetches
// its rows eagerly in NewState, stores a plain exported Go slice (Rows) plus an
// EXPLICIT CURSOR (Offset), and rebuilds the Arrow batch in Process.
//
// WHY A CURSOR, NOT A bool Done (the HTTP-continuation fix):
//
// Over the HTTP transport the worker is STATELESS across exchanges — there is no
// long-lived process holding the live state between Process ticks. Instead the
// framework round-trips the producer state through an opaque continuation token:
// after each tick it gob-encodes the state (snapshotting the LIVE user state),
// the client returns the token, and the worker resumes by gob-decoding it. The
// HTTP server emits at most `producerBatchLimit` data batches per response
// (the SDK sets this to 1), so a producer that has more to emit is always
// resumed mid-stream from its token.
//
// The position MUST therefore live in the serialized state. A bare `Done bool`
// that is only flipped *after* the single Emit does not reliably survive the
// limit-1 continuation boundary: the resumed tick observes the pre-Emit state,
// re-emits the same rows, and the scan never terminates (an infinite loop that
// pins the worker — subprocess/unix keep the live state in memory, so they were
// unaffected and hid the bug). Carrying an explicit Offset that Process advances
// BEFORE yielding makes the snapshot authoritative: the resume sees the advanced
// Offset and emits the next slice (or Finishes when Offset >= len(Rows)). This
// is the reference pattern for every streaming Go table function over HTTP.
//
// rowsPerTick bounds how many rows each Process tick emits. Emitting the whole
// result in one batch is fine for these small NVD result sets, but emitting a
// bounded slice and advancing the cursor each tick is what makes the cursor
// observable across the continuation boundary (and scales to large results).
const rowsPerTick = 64

// CursorState is the shared streaming cursor embedded by every table-function
// state: the eagerly fetched rows plus the offset of the next unemitted row.
// Both fields are exported so gob round-trips them through the HTTP continuation
// token. The TYPE is exported too (CursorState, not cursorState) because the SDK
// counts a state struct's exported FIELDS at registration to verify it is
// gob-encodable — an embedded field named after an unexported type would not be
// counted and the worker would panic at startup.
type CursorState struct {
	Rows   []CVERow
	Offset int
}

// nextSlice returns the next bounded slice of rows to emit and advances the
// cursor past them. It reports done=true once the cursor has consumed all rows,
// at which point Process should call out.Finish().
func (c *CursorState) nextSlice() (slice []CVERow, done bool) {
	if c.Offset >= len(c.Rows) {
		return nil, true
	}
	end := c.Offset + rowsPerTick
	if end > len(c.Rows) {
		end = len(c.Rows)
	}
	slice = c.Rows[c.Offset:end]
	c.Offset = end
	return slice, false
}

// ===========================================================================
// Offline scalar functions (no network) — pure CVSS math.
// ===========================================================================

// ---------------------------------------------------------------------------
// cvss_severity(score DOUBLE) -> VARCHAR
// ---------------------------------------------------------------------------

// CVSSSeverityFunction maps a numeric CVSS base score to its qualitative band.
type CVSSSeverityFunction struct{}

func (f *CVSSSeverityFunction) Name() string { return "cvss_severity" }

func (f *CVSSSeverityFunction) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Map a CVSS base score (0.0-10.0) to NONE/LOW/MEDIUM/HIGH/CRITICAL",
		Stability:   vgi.StabilityConsistent,
		ReturnType:  arrow.BinaryTypes.String,
		Categories:  []string{"cve", "cvss"},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT cve.main.cvss_severity(9.8);",
				Description: "Map a numeric CVSS base score to its qualitative band (returns 'CRITICAL').",
			},
		},
	}
}

func (f *CVSSSeverityFunction) ArgumentSpecs() []vgi.ArgSpec {
	return []vgi.ArgSpec{
		{Name: "score", Position: 0, ArrowType: "double", Doc: "CVSS base score"},
	}
}

func (f *CVSSSeverityFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindResult(arrow.BinaryTypes.String)
}

func (f *CVSSSeverityFunction) Process(_ context.Context, params *vgi.ProcessParams, batch arrow.RecordBatch) (arrow.RecordBatch, error) {
	return vgi.MapColumn(params, batch, 0, array.NewStringBuilder,
		func(col arrow.Array, i int) string {
			return Severity(vgi.GetFloat64Value(col, i))
		})
}

// NewCVSSSeverityFunction builds the registerable scalar function.
func NewCVSSSeverityFunction() vgi.ScalarFunction {
	return &CVSSSeverityFunction{}
}

// ---------------------------------------------------------------------------
// cvss_base_score(vector VARCHAR) -> DOUBLE
// ---------------------------------------------------------------------------

// CVSSBaseScoreFunction computes a CVSS v3.1 base score from a vector string.
type CVSSBaseScoreFunction struct{}

func (f *CVSSBaseScoreFunction) Name() string { return "cvss_base_score" }

func (f *CVSSBaseScoreFunction) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Compute the CVSS v3.1 base score from a vector string",
		Stability:   vgi.StabilityConsistent,
		ReturnType:  arrow.PrimitiveTypes.Float64,
		Categories:  []string{"cve", "cvss"},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT cve.main.cvss_base_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');",
				Description: "Compute the CVSS v3.1 base score for the Log4Shell vector (returns 9.8).",
			},
		},
	}
}

func (f *CVSSBaseScoreFunction) ArgumentSpecs() []vgi.ArgSpec {
	return []vgi.ArgSpec{
		{Name: "vector", Position: 0, ArrowType: "varchar", Doc: "CVSS v3.1 vector string"},
	}
}

func (f *CVSSBaseScoreFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindResult(arrow.PrimitiveTypes.Float64)
}

func (f *CVSSBaseScoreFunction) Process(_ context.Context, params *vgi.ProcessParams, batch arrow.RecordBatch) (arrow.RecordBatch, error) {
	// A malformed vector in any row fails the whole call with a clear error;
	// this mirrors how DuckDB scalar functions surface bad inputs.
	var firstErr error
	out, mapErr := vgi.MapColumn(params, batch, 0, array.NewFloat64Builder,
		func(col arrow.Array, i int) float64 {
			s, err := BaseScore(vgi.GetStringValue(col, i))
			if err != nil && firstErr == nil {
				firstErr = err
			}
			return s
		})
	if firstErr != nil {
		return nil, firstErr
	}
	return out, mapErr
}

// NewCVSSBaseScoreFunction builds the registerable scalar function.
func NewCVSSBaseScoreFunction() vgi.ScalarFunction {
	return &CVSSBaseScoreFunction{}
}

// ===========================================================================
// Table functions (NVD 2.0 API) — each accepts named base_url + api_key opts.
// ===========================================================================

// clientFrom builds an NVD client from the shared base_url / api_key options.
func clientFrom(baseURL, apiKey string) *Client {
	return NewClient(baseURL, apiKey)
}

// ---------------------------------------------------------------------------
// cve(cve_id) -> (id, description, cvss_score, cvss_severity, cvss_vector,
//                 published, last_modified, cwe)
// ---------------------------------------------------------------------------

var cveSchema = arrow.NewSchema([]arrow.Field{
	{Name: "id", Type: arrow.BinaryTypes.String},
	{Name: "description", Type: arrow.BinaryTypes.String},
	{Name: "cvss_score", Type: arrow.PrimitiveTypes.Float64, Nullable: true},
	{Name: "cvss_severity", Type: arrow.BinaryTypes.String},
	{Name: "cvss_vector", Type: arrow.BinaryTypes.String},
	{Name: "published", Type: arrow.BinaryTypes.String},
	{Name: "last_modified", Type: arrow.BinaryTypes.String},
	{Name: "cwe", Type: arrow.BinaryTypes.String},
}, nil)

type cveArgs struct {
	CVEID   string `vgi:"pos=0,doc=CVE identifier (e.g. CVE-2021-44228)"`
	BaseURL string `vgi:"name=base_url,default=,doc=Override the NVD API base URL"`
	APIKey  string `vgi:"name=api_key,default=,doc=NVD API key (raises the rate limit)"`
}

// cveState holds the at-most-one fetched row (gob-encodable) plus the cursor.
type cveState struct {
	CursorState
}

// CVEFunction fetches one CVE by ID.
type CVEFunction struct{}

var _ vgi.TypedTableFunc[cveState] = (*CVEFunction)(nil)

func (f *CVEFunction) Name() string { return "cve" }

func (f *CVEFunction) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Fetch a single CVE record by ID from the NVD 2.0 API",
		Stability:   vgi.StabilityVolatile,
		Categories:  []string{"cve", "nvd"},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT * FROM cve.main.cve('CVE-2021-44228');",
				Description: "Fetch the Log4Shell CVE record (description, CVSS score/severity/vector, dates, CWE).",
			},
		},
		Tags: map[string]string{
			"vgi.columns_md": "| column | type | description |\n" +
				"|---|---|---|\n" +
				"| `id` | VARCHAR | The CVE identifier, e.g. `CVE-2021-44228`. |\n" +
				"| `description` | VARCHAR | English description of the vulnerability. |\n" +
				"| `cvss_score` | DOUBLE | CVSS base score (0.0-10.0); NULL when the CVE has no metrics yet. |\n" +
				"| `cvss_severity` | VARCHAR | Qualitative band: NONE/LOW/MEDIUM/HIGH/CRITICAL. |\n" +
				"| `cvss_vector` | VARCHAR | The CVSS vector string. |\n" +
				"| `published` | VARCHAR | Publication timestamp (ISO 8601). |\n" +
				"| `last_modified` | VARCHAR | Last-modified timestamp (ISO 8601). |\n" +
				"| `cwe` | VARCHAR | Associated CWE identifier(s). |",
		},
	}
}

func (f *CVEFunction) ArgumentSpecs() []vgi.ArgSpec { return vgi.DeriveArgSpecs(cveArgs{}) }

func (f *CVEFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(cveSchema)
}

func (f *CVEFunction) NewState(params *vgi.ProcessParams) (*cveState, error) {
	var args cveArgs
	if err := vgi.BindArgs(params.Args, &args); err != nil {
		return nil, err
	}
	if isNullArg(params.Args, 0) {
		return &cveState{}, nil
	}
	row, err := clientFrom(args.BaseURL, args.APIKey).FetchCVE(context.Background(), args.CVEID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return &cveState{}, nil
	}
	return &cveState{CursorState: CursorState{Rows: []CVERow{*row}}}, nil
}

func (f *CVEFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *cveState, out *vgirpc.OutputCollector) error {
	r, done := state.nextSlice()
	if done {
		return out.Finish()
	}
	n := int64(len(r))
	batch := array.NewRecordBatch(cveSchema, []arrow.Array{
		vgi.BuildStringArray(n, func(i int64) string { return r[i].ID }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Description }),
		buildNullableScore(r),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].SeverityStr }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Vector }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Published }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].LastModified }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].CWE }),
	}, n)
	defer batch.Release()
	return out.Emit(batch)
}

// NewCVEFunction builds the registerable table function.
func NewCVEFunction() vgi.TableFunction {
	return vgi.AsTableFunction[cveState](&CVEFunction{})
}

// ---------------------------------------------------------------------------
// cve_search(keyword) -> (id, description, cvss_score, cvss_severity, published)
// ---------------------------------------------------------------------------

var cveSearchSchema = arrow.NewSchema([]arrow.Field{
	{Name: "id", Type: arrow.BinaryTypes.String},
	{Name: "description", Type: arrow.BinaryTypes.String},
	{Name: "cvss_score", Type: arrow.PrimitiveTypes.Float64, Nullable: true},
	{Name: "cvss_severity", Type: arrow.BinaryTypes.String},
	{Name: "published", Type: arrow.BinaryTypes.String},
}, nil)

type cveSearchArgs struct {
	Keyword string `vgi:"pos=0,doc=Keyword to search CVE descriptions"`
	BaseURL string `vgi:"name=base_url,default=,doc=Override the NVD API base URL"`
	APIKey  string `vgi:"name=api_key,default=,doc=NVD API key (raises the rate limit)"`
}

type cveSearchState struct {
	CursorState
}

// CVESearchFunction runs a paginated keyword search.
type CVESearchFunction struct{}

var _ vgi.TypedTableFunc[cveSearchState] = (*CVESearchFunction)(nil)

func (f *CVESearchFunction) Name() string { return "cve_search" }

func (f *CVESearchFunction) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Keyword-search the NVD 2.0 API (paginated, bounded to 100 results)",
		Stability:   vgi.StabilityVolatile,
		Categories:  []string{"cve", "nvd"},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT * FROM cve.main.cve_search('log4j') ORDER BY cvss_score DESC;",
				Description: "Keyword-search CVE descriptions for 'log4j', highest CVSS score first.",
			},
		},
		Tags: map[string]string{
			"vgi.columns_md": "| column | type | description |\n" +
				"|---|---|---|\n" +
				"| `id` | VARCHAR | The CVE identifier. |\n" +
				"| `description` | VARCHAR | English description of the vulnerability. |\n" +
				"| `cvss_score` | DOUBLE | CVSS base score (0.0-10.0); NULL when the CVE has no metrics yet. |\n" +
				"| `cvss_severity` | VARCHAR | Qualitative band: NONE/LOW/MEDIUM/HIGH/CRITICAL. |\n" +
				"| `published` | VARCHAR | Publication timestamp (ISO 8601). |",
		},
	}
}

func (f *CVESearchFunction) ArgumentSpecs() []vgi.ArgSpec { return vgi.DeriveArgSpecs(cveSearchArgs{}) }

func (f *CVESearchFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(cveSearchSchema)
}

func (f *CVESearchFunction) NewState(params *vgi.ProcessParams) (*cveSearchState, error) {
	var args cveSearchArgs
	if err := vgi.BindArgs(params.Args, &args); err != nil {
		return nil, err
	}
	if isNullArg(params.Args, 0) {
		return &cveSearchState{}, nil
	}
	rows, err := clientFrom(args.BaseURL, args.APIKey).SearchKeyword(context.Background(), args.Keyword)
	if err != nil {
		return nil, err
	}
	return &cveSearchState{CursorState: CursorState{Rows: rows}}, nil
}

func (f *CVESearchFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *cveSearchState, out *vgirpc.OutputCollector) error {
	r, done := state.nextSlice()
	if done {
		return out.Finish()
	}
	n := int64(len(r))
	batch := array.NewRecordBatch(cveSearchSchema, []arrow.Array{
		vgi.BuildStringArray(n, func(i int64) string { return r[i].ID }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Description }),
		buildNullableScore(r),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].SeverityStr }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Published }),
	}, n)
	defer batch.Release()
	return out.Emit(batch)
}

// NewCVESearchFunction builds the registerable table function.
func NewCVESearchFunction() vgi.TableFunction {
	return vgi.AsTableFunction[cveSearchState](&CVESearchFunction{})
}

// ---------------------------------------------------------------------------
// cpe_cves(cpe) -> (cve_id, cvss_score, cvss_severity)
// ---------------------------------------------------------------------------

var cpeCVEsSchema = arrow.NewSchema([]arrow.Field{
	{Name: "cve_id", Type: arrow.BinaryTypes.String},
	{Name: "cvss_score", Type: arrow.PrimitiveTypes.Float64, Nullable: true},
	{Name: "cvss_severity", Type: arrow.BinaryTypes.String},
}, nil)

type cpeCVEsArgs struct {
	CPE     string `vgi:"pos=0,doc=CPE 2.3 name (e.g. cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*)"`
	BaseURL string `vgi:"name=base_url,default=,doc=Override the NVD API base URL"`
	APIKey  string `vgi:"name=api_key,default=,doc=NVD API key (raises the rate limit)"`
}

type cpeCVEsState struct {
	CursorState
}

// CPECVEsFunction lists CVEs for a CPE name.
type CPECVEsFunction struct{}

var _ vgi.TypedTableFunc[cpeCVEsState] = (*CPECVEsFunction)(nil)

func (f *CPECVEsFunction) Name() string { return "cpe_cves" }

func (f *CPECVEsFunction) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "List CVEs affecting a CPE name from the NVD 2.0 API (paginated, bounded)",
		Stability:   vgi.StabilityVolatile,
		Categories:  []string{"cve", "nvd", "cpe"},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT * FROM cve.main.cpe_cves('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*');",
				Description: "List the CVEs affecting a specific CPE 2.3 product (Apache Log4j 2.14.1).",
			},
		},
		Tags: map[string]string{
			"vgi.columns_md": "| column | type | description |\n" +
				"|---|---|---|\n" +
				"| `cve_id` | VARCHAR | The CVE identifier affecting the CPE. |\n" +
				"| `cvss_score` | DOUBLE | CVSS base score (0.0-10.0); NULL when the CVE has no metrics yet. |\n" +
				"| `cvss_severity` | VARCHAR | Qualitative band: NONE/LOW/MEDIUM/HIGH/CRITICAL. |",
		},
	}
}

func (f *CPECVEsFunction) ArgumentSpecs() []vgi.ArgSpec { return vgi.DeriveArgSpecs(cpeCVEsArgs{}) }

func (f *CPECVEsFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(cpeCVEsSchema)
}

func (f *CPECVEsFunction) NewState(params *vgi.ProcessParams) (*cpeCVEsState, error) {
	var args cpeCVEsArgs
	if err := vgi.BindArgs(params.Args, &args); err != nil {
		return nil, err
	}
	if isNullArg(params.Args, 0) {
		return &cpeCVEsState{}, nil
	}
	rows, err := clientFrom(args.BaseURL, args.APIKey).CVEsForCPE(context.Background(), args.CPE)
	if err != nil {
		return nil, err
	}
	return &cpeCVEsState{CursorState: CursorState{Rows: rows}}, nil
}

func (f *CPECVEsFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *cpeCVEsState, out *vgirpc.OutputCollector) error {
	r, done := state.nextSlice()
	if done {
		return out.Finish()
	}
	n := int64(len(r))
	batch := array.NewRecordBatch(cpeCVEsSchema, []arrow.Array{
		vgi.BuildStringArray(n, func(i int64) string { return r[i].ID }),
		buildNullableScore(r),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].SeverityStr }),
	}, n)
	defer batch.Release()
	return out.Emit(batch)
}

// NewCPECVEsFunction builds the registerable table function.
func NewCPECVEsFunction() vgi.TableFunction {
	return vgi.AsTableFunction[cpeCVEsState](&CPECVEsFunction{})
}

// ===========================================================================
// helpers
// ===========================================================================

// buildNullableScore builds a Float64 array where a nil Score yields SQL NULL,
// so a CVE with no CVSS metrics surfaces a NULL score rather than 0.
func buildNullableScore(rows []CVERow) arrow.Array {
	b := array.NewFloat64Builder(memory.NewGoAllocator())
	defer b.Release()
	b.Reserve(len(rows))
	for _, r := range rows {
		if r.Score == nil {
			b.AppendNull()
		} else {
			b.Append(*r.Score)
		}
	}
	return b.NewArray()
}

// isNullArg reports whether positional argument pos is present and NULL.
func isNullArg(args *vgi.Arguments, pos int) bool {
	if args == nil {
		return true
	}
	col, err := args.GetColumn(pos)
	if err != nil {
		return false
	}
	return col.Len() == 0 || col.IsNull(0)
}

// Register registers all CVE functions (offline scalars + NVD table functions).
func Register(w *vgi.Worker) {
	w.RegisterScalar(NewCVSSSeverityFunction())
	w.RegisterScalar(NewCVSSBaseScoreFunction())
	w.RegisterTable(NewCVEFunction())
	w.RegisterTable(NewCVESearchFunction())
	w.RegisterTable(NewCPECVEsFunction())
}
