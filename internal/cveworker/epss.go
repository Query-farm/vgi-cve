// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-rpc-go/vgirpc"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
)

// DefaultEPSSURL is FIRST's EPSS API endpoint. epss() accepts a base_url
// named option that replaces this whole URL (the E2E points it at the mock).
const DefaultEPSSURL = "https://api.first.org/data/v1/epss"

// epssMaxCVEParam is the longest comma-joined `cve=` value sent in one request.
// The EPSS API documents a 2000-character maximum for that parameter, so the
// input list is split into chunks that each stay under it (~140 CVE ids).
const epssMaxCVEParam = 2000

// epssPageLimit is the page size requested per call; responses are paged with
// offset until the reported total is consumed.
const epssPageLimit = 1000

// MaxEPSSCVEs bounds how many distinct CVE ids one epss() call will score, so
// an accidental huge list cannot fire hundreds of API requests.
const MaxEPSSCVEs = 10000

// EPSSRow is one EPSS score. Exported + gob-encodable (table-function state).
type EPSSRow struct {
	CVEID      string
	EPSS       float64
	Percentile float64
	Date       string
}

type epssResponse struct {
	Status string `json:"status"`
	Total  int    `json:"total"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
	Data   []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

// FetchEPSS scores cveIDs (deduplicated, upper-cased) against the EPSS API at
// endpoint (empty → DefaultEPSSURL), optionally for a historical date
// (YYYY-MM-DD; empty → latest). CVEs EPSS has no score for are omitted.
func FetchEPSS(ctx context.Context, endpoint string, cveIDs []string, date string) ([]EPSSRow, error) {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = DefaultEPSSURL
	}
	date = strings.TrimSpace(date)
	if date != "" {
		if _, ok := parseDate(date); !ok || len(date) != 10 {
			return nil, fmt.Errorf("epss: date must be YYYY-MM-DD, got %q", date)
		}
	}
	ids := normalizeCVEIDs(cveIDs)
	if len(ids) > MaxEPSSCVEs {
		return nil, fmt.Errorf("epss: %d distinct CVE ids exceeds the per-call limit of %d", len(ids), MaxEPSSCVEs)
	}
	hc := &http.Client{Timeout: defaultTimeout}
	var rows []EPSSRow
	for _, chunk := range chunkCVEParam(ids, epssMaxCVEParam) {
		offset := 0
		for {
			q := url.Values{}
			q.Set("cve", chunk)
			if date != "" {
				q.Set("date", date)
			}
			q.Set("limit", strconv.Itoa(epssPageLimit))
			q.Set("offset", strconv.Itoa(offset))
			sep := "?"
			if strings.Contains(endpoint, "?") {
				sep = "&"
			}
			body, err := doJSON(ctx, hc, "epss", http.MethodGet, endpoint+sep+q.Encode(), nil)
			if err != nil {
				return nil, err
			}
			var resp epssResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				return nil, fmt.Errorf("epss: decode JSON response: %w", err)
			}
			for _, d := range resp.Data {
				e, err1 := strconv.ParseFloat(d.EPSS, 64)
				p, err2 := strconv.ParseFloat(d.Percentile, 64)
				if err1 != nil || err2 != nil {
					return nil, fmt.Errorf("epss: bad score for %s (epss=%q percentile=%q)", d.CVE, d.EPSS, d.Percentile)
				}
				rows = append(rows, EPSSRow{CVEID: d.CVE, EPSS: e, Percentile: p, Date: d.Date})
			}
			offset += len(resp.Data)
			if len(resp.Data) == 0 || offset >= resp.Total {
				break
			}
		}
	}
	return rows, nil
}

// normalizeCVEIDs trims, upper-cases, drops empties, and deduplicates
// (preserving first-seen order).
func normalizeCVEIDs(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// chunkCVEParam joins ids into comma-separated groups no longer than max chars.
func chunkCVEParam(ids []string, maxLen int) []string {
	var out []string
	var b strings.Builder
	for _, id := range ids {
		if b.Len() > 0 && b.Len()+1+len(id) > maxLen {
			out = append(out, b.String())
			b.Reset()
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(id)
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

var epssSchema = arrow.NewSchema([]arrow.Field{
	{Name: "cve_id", Type: arrow.BinaryTypes.String},
	{Name: "epss", Type: arrow.PrimitiveTypes.Float64},
	{Name: "percentile", Type: arrow.PrimitiveTypes.Float64},
	{Name: "date", Type: arrow.FixedWidthTypes.Date32, Nullable: true},
}, nil)

// epssArgs declares the argument specs. The positional list is read directly
// from the argument column in NewState (vgi.BindArgs does not extract LIST
// scalars), so BindArgs only fills the named options via epssNamedArgs.
type epssArgs struct {
	CVEIDs  []string `vgi:"pos=0,doc=List of CVE identifiers to score (e.g. ['CVE-2021-44228'])"`
	Date    string   `vgi:"name=date,default=,doc=Historical score date as YYYY-MM-DD (default: latest)"`
	BaseURL string   `vgi:"name=base_url,default=,doc=Override the FIRST EPSS API endpoint URL"`
}

type epssNamedArgs struct {
	Date    string `vgi:"name=date,default="`
	BaseURL string `vgi:"name=base_url,default="`
}

type epssState struct {
	Rows   []EPSSRow
	Offset int
}

// EPSSFunction scores CVEs with FIRST's Exploit Prediction Scoring System.
type EPSSFunction struct{}

var _ vgi.TypedTableFunc[epssState] = (*EPSSFunction)(nil)

func (f *EPSSFunction) Name() string { return "epss" }

func (f *EPSSFunction) Metadata() vgi.FunctionMetadata {
	examples := []vgi.CatalogExample{
		{
			SQL: "SELECT cve_id, epss, percentile, date " +
				"FROM cve.main.epss(['CVE-2021-44228', 'CVE-2022-22965']) ORDER BY epss DESC;",
			Description: "Get today's EPSS exploitation probability and percentile for Log4Shell and Spring4Shell.",
		},
		{
			SQL:         "SELECT cve_id, epss, percentile FROM cve.main.epss(['CVE-2021-44228'], date := '2023-03-01');",
			Description: "Look up Log4Shell's historical EPSS score as published on 2023-03-01.",
		},
		ExamplePrioritizeCPE,
	}
	return vgi.FunctionMetadata{
		Description: "Score CVEs with FIRST EPSS (probability of exploitation in the next 30 days)",
		Stability:   vgi.StabilityVolatile,
		Categories:  []string{"cve", "epss", "exploit"},
		Examples:    examples,
		Tags: withExamples(withResultSchema(
			"EPSS Exploit Prediction Scores",
			"Score a list of CVE identifiers with FIRST's Exploit Prediction Scoring System (EPSS): "+
				"the modeled probability (0-1) that each CVE is exploited in the wild within the next 30 "+
				"days, plus its percentile rank among all scored CVEs. Pass a `VARCHAR[]` list literal; "+
				"table-function arguments cannot be subqueries, so to score a dynamic set first store the "+
				"list in a DuckDB variable and pass it with getvariable(). Ids are "+
				"deduplicated (case-insensitively) and "+
				"batched into as few API calls as the API's 2000-character cve parameter allows. "+
				"Optional date := 'YYYY-MM-DD' returns historical scores. CVEs without an EPSS score "+
				"are omitted. Data from FIRST (first.org/epss).",
			"EPSS exploitation probability and percentile for a list of CVEs, e.g. "+
				"`epss(['CVE-2021-44228'])`.",
			`["epss","exploit prediction","exploit probability","first","exploitation likelihood","percentile","risk score","patch prioritization","threat","vulnerability prioritization"]`,
			"Exploit Intelligence",
			[]resultColumn{
				{"cve_id", "VARCHAR", "The scored CVE identifier."},
				{"epss", "DOUBLE", "EPSS probability (0.0-1.0) that the CVE is exploited in the next 30 days."},
				{"percentile", "DOUBLE", "Percentile rank (0.0-1.0) of this score among all EPSS-scored CVEs."},
				{"date", "DATE", "The date the EPSS score was published for."},
			},
		), examples),
	}
}

func (f *EPSSFunction) ArgumentSpecs() []vgi.ArgSpec { return vgi.DeriveArgSpecs(epssArgs{}) }

func (f *EPSSFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(epssSchema)
}

func (f *EPSSFunction) NewState(params *vgi.ProcessParams) (*epssState, error) {
	var named epssNamedArgs
	if err := vgi.BindArgs(params.Args, &named); err != nil {
		return nil, err
	}
	ids, err := stringListArg(params.Args, 0)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return &epssState{}, nil
	}
	rows, err := FetchEPSS(context.Background(), named.BaseURL, ids, named.Date)
	if err != nil {
		return nil, err
	}
	return &epssState{Rows: rows}, nil
}

func (f *EPSSFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *epssState, out *vgirpc.OutputCollector) error {
	r, done := nextRows(state.Rows, &state.Offset)
	if done {
		return out.Finish()
	}
	n := len(r)
	n64 := int64(n)
	batch := array.NewRecordBatch(epssSchema, []arrow.Array{
		vgi.BuildStringArray(n64, func(i int64) string { return r[i].CVEID }),
		vgi.BuildFloat64Array(n64, func(i int64) float64 { return r[i].EPSS }),
		vgi.BuildFloat64Array(n64, func(i int64) float64 { return r[i].Percentile }),
		buildNullableDate(n, func(i int) string { return r[i].Date }),
	}, n64)
	defer batch.Release()
	return out.Emit(batch)
}

// NewEPSSFunction builds the registerable table function.
func NewEPSSFunction() vgi.TableFunction {
	return vgi.AsTableFunction[epssState](&EPSSFunction{})
}

// stringListArg reads positional argument pos as a VARCHAR[] (NULL list or
// NULL elements are skipped). A plain VARCHAR is accepted as a one-element
// list, so a single id also works if the engine passes it uncast.
func stringListArg(args *vgi.Arguments, pos int) ([]string, error) {
	if args == nil {
		return nil, nil
	}
	col, err := args.GetColumn(pos)
	if err != nil || col == nil || col.Len() == 0 || col.IsNull(0) {
		return nil, nil //nolint:nilerr // a missing/NULL list means "no ids", not an error
	}
	if lst, ok := col.(array.ListLike); ok {
		start, end := lst.ValueOffsets(0)
		vals := lst.ListValues()
		out := make([]string, 0, end-start)
		for i := int(start); i < int(end); i++ {
			if vals.IsNull(i) {
				continue
			}
			v, ok := strAt(vals, i)
			if !ok {
				return nil, fmt.Errorf("expected a VARCHAR[] list, got %s", col.DataType())
			}
			out = append(out, v)
		}
		return out, nil
	}
	if v, ok := strAt(col, 0); ok {
		return []string{v}, nil
	}
	return nil, fmt.Errorf("expected a VARCHAR[] list, got %s", col.DataType())
}

// strAt reads element i of any Arrow string-like array.
func strAt(a arrow.Array, i int) (string, bool) {
	switch c := a.(type) {
	case *array.String:
		return c.Value(i), true
	case *array.LargeString:
		return c.Value(i), true
	case *array.StringView:
		return c.Value(i), true
	case *array.Dictionary:
		return strAt(c.Dictionary(), c.GetValueIndex(i))
	}
	return "", false
}
