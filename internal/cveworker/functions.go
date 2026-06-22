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
// its rows eagerly in NewState, stores plain exported Go slices plus a Done
// flag, and rebuilds the Arrow batch in Process.

// emitState carries the "already emitted" flag shared by the table functions.
type emitState struct {
	Done bool
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

// cveState holds the at-most-one fetched row (gob-encodable) plus the emit flag.
type cveState struct {
	emitState
	Rows []CVERow
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
	return &cveState{Rows: []CVERow{*row}}, nil
}

func (f *CVEFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *cveState, out *vgirpc.OutputCollector) error {
	if state.Done {
		return out.Finish()
	}
	state.Done = true
	r := state.Rows
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
	emitState
	Rows []CVERow
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
	return &cveSearchState{Rows: rows}, nil
}

func (f *CVESearchFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *cveSearchState, out *vgirpc.OutputCollector) error {
	if state.Done {
		return out.Finish()
	}
	state.Done = true
	r := state.Rows
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
	emitState
	Rows []CVERow
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
	return &cpeCVEsState{Rows: rows}, nil
}

func (f *CPECVEsFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *cpeCVEsState, out *vgirpc.OutputCollector) error {
	if state.Done {
		return out.Finish()
	}
	state.Done = true
	r := state.Rows
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
