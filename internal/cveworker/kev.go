// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-rpc-go/vgirpc"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
)

// DefaultKEVURL is CISA's Known Exploited Vulnerabilities catalog JSON feed
// (US government work, public domain). kev()/kev_cve() accept a base_url
// named option that replaces this whole URL (the E2E points it at the mock).
const DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// kevCacheTTL bounds how long a fetched KEV feed is reused in-process. CISA
// updates the catalog at most a few times a day, and the feed is ~1.5 MB, so a
// query that calls kev() more than once (or joins kev() with kev_cve()) should
// not refetch it. The cache is keyed by URL and lives only in worker memory.
const kevCacheTTL = 15 * time.Minute

// KEVRow is one entry of the CISA KEV catalog, flattened for SQL. All fields
// are exported and gob-encodable (it is carried in table-function state).
type KEVRow struct {
	CVEID                      string
	VendorProject              string
	Product                    string
	VulnerabilityName          string
	DateAdded                  string
	ShortDescription           string
	RequiredAction             string
	DueDate                    string
	KnownRansomwareCampaignUse string
	Notes                      string
	CWEs                       []string
}

type kevFeed struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

type kevCacheEntry struct {
	rows    []KEVRow
	fetched time.Time
}

var (
	kevCacheMu sync.Mutex
	kevCache   = map[string]kevCacheEntry{}
)

// FetchKEV downloads (or reuses a recent in-process copy of) the KEV catalog
// at feedURL; an empty feedURL means DefaultKEVURL.
func FetchKEV(ctx context.Context, feedURL string) ([]KEVRow, error) {
	if strings.TrimSpace(feedURL) == "" {
		feedURL = DefaultKEVURL
	}
	kevCacheMu.Lock()
	if e, ok := kevCache[feedURL]; ok && time.Since(e.fetched) < kevCacheTTL {
		kevCacheMu.Unlock()
		return e.rows, nil
	}
	kevCacheMu.Unlock()

	body, err := doJSON(ctx, &http.Client{Timeout: defaultTimeout}, "kev", http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	var feed kevFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("kev: decode JSON feed: %w", err)
	}
	if feed.Vulnerabilities == nil {
		return nil, fmt.Errorf("kev: feed has no \"vulnerabilities\" array (is base_url the KEV JSON feed?)")
	}
	rows := make([]KEVRow, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		cwes := v.CWEs
		if cwes == nil {
			cwes = []string{}
		}
		rows = append(rows, KEVRow{
			CVEID:                      strings.TrimSpace(v.CVEID),
			VendorProject:              v.VendorProject,
			Product:                    v.Product,
			VulnerabilityName:          v.VulnerabilityName,
			DateAdded:                  v.DateAdded,
			ShortDescription:           v.ShortDescription,
			RequiredAction:             v.RequiredAction,
			DueDate:                    v.DueDate,
			KnownRansomwareCampaignUse: v.KnownRansomwareCampaignUse,
			Notes:                      v.Notes,
			CWEs:                       cwes,
		})
	}
	kevCacheMu.Lock()
	kevCache[feedURL] = kevCacheEntry{rows: rows, fetched: time.Now()}
	kevCacheMu.Unlock()
	return rows, nil
}

var kevSchema = arrow.NewSchema([]arrow.Field{
	{Name: "cve_id", Type: arrow.BinaryTypes.String},
	{Name: "vendor_project", Type: arrow.BinaryTypes.String},
	{Name: "product", Type: arrow.BinaryTypes.String},
	{Name: "vulnerability_name", Type: arrow.BinaryTypes.String},
	{Name: "date_added", Type: arrow.FixedWidthTypes.Date32, Nullable: true},
	{Name: "short_description", Type: arrow.BinaryTypes.String},
	{Name: "required_action", Type: arrow.BinaryTypes.String},
	{Name: "due_date", Type: arrow.FixedWidthTypes.Date32, Nullable: true},
	{Name: "known_ransomware_campaign_use", Type: arrow.BinaryTypes.String},
	{Name: "notes", Type: arrow.BinaryTypes.String, Nullable: true},
	{Name: "cwes", Type: stringListType},
}, nil)

var kevColumns = []resultColumn{
	{"cve_id", "VARCHAR", "The CVE identifier CISA lists as known exploited, e.g. CVE-2021-44228."},
	{"vendor_project", "VARCHAR", "Vendor or project that owns the affected product, e.g. Apache."},
	{"product", "VARCHAR", "Affected product name, e.g. Log4j2."},
	{"vulnerability_name", "VARCHAR", "CISA's short title for the vulnerability."},
	{"date_added", "DATE", "Date CISA added the CVE to the KEV catalog."},
	{"short_description", "VARCHAR", "CISA's one-paragraph description of the vulnerability."},
	{"required_action", "VARCHAR", "The remediation action CISA requires of US federal agencies."},
	{"due_date", "DATE", "Remediation due date for US federal agencies under BOD 22-01."},
	{"known_ransomware_campaign_use", "VARCHAR", "'Known' when CISA knows of ransomware campaigns using the CVE, else 'Unknown'."},
	{"notes", "VARCHAR", "Free-text notes and reference URLs; NULL when CISA gave none."},
	{"cwes", "VARCHAR[]", "CWE identifiers CISA associates with the CVE (possibly empty)."},
}

// kevBatch builds one Arrow batch for a slice of KEV rows.
func kevBatch(r []KEVRow) arrow.RecordBatch {
	n := len(r)
	n64 := int64(n)
	return array.NewRecordBatch(kevSchema, []arrow.Array{
		vgi.BuildStringArray(n64, func(i int64) string { return r[i].CVEID }),
		vgi.BuildStringArray(n64, func(i int64) string { return r[i].VendorProject }),
		vgi.BuildStringArray(n64, func(i int64) string { return r[i].Product }),
		vgi.BuildStringArray(n64, func(i int64) string { return r[i].VulnerabilityName }),
		buildNullableDate(n, func(i int) string { return r[i].DateAdded }),
		vgi.BuildStringArray(n64, func(i int64) string { return r[i].ShortDescription }),
		vgi.BuildStringArray(n64, func(i int64) string { return r[i].RequiredAction }),
		buildNullableDate(n, func(i int) string { return r[i].DueDate }),
		vgi.BuildStringArray(n64, func(i int64) string { return r[i].KnownRansomwareCampaignUse }),
		buildNullableString(n, func(i int) string { return r[i].Notes }),
		buildStringList(n, func(i int) []string { return r[i].CWEs }),
	}, n64)
}

// kevState is the gob-encodable cursor shared by kev() and kev_cve().
type kevState struct {
	Rows   []KEVRow
	Offset int
}

func processKEV(state *kevState, out *vgirpc.OutputCollector) error {
	r, done := nextRows(state.Rows, &state.Offset)
	if done {
		return out.Finish()
	}
	batch := kevBatch(r)
	defer batch.Release()
	return out.Emit(batch)
}

// ---------------------------------------------------------------------------
// kev() -> the whole KEV catalog
// ---------------------------------------------------------------------------

type kevArgs struct {
	BaseURL string `vgi:"name=base_url,default=,doc=Override the CISA KEV JSON feed URL (the whole URL)"`
}

// KEVFunction lists the CISA Known Exploited Vulnerabilities catalog.
type KEVFunction struct{}

var _ vgi.TypedTableFunc[kevState] = (*KEVFunction)(nil)

func (f *KEVFunction) Name() string { return "kev" }

func (f *KEVFunction) Metadata() vgi.FunctionMetadata {
	examples := []vgi.CatalogExample{
		{
			SQL: "SELECT cve_id, vendor_project, product, date_added, due_date " +
				"FROM cve.main.kev() WHERE known_ransomware_campaign_use = 'Known' " +
				"ORDER BY date_added DESC LIMIT 10;",
			Description: "List the ten most recently added KEV entries that CISA knows are used in ransomware campaigns.",
		},
		{
			SQL: "SELECT vendor_project, count(*) AS exploited_cves FROM cve.main.kev() " +
				"GROUP BY vendor_project ORDER BY exploited_cves DESC, vendor_project LIMIT 5;",
			Description: "Rank the five vendors with the most known-exploited CVEs in the KEV catalog.",
		},
		ExamplePrioritizeCPE,
	}
	return vgi.FunctionMetadata{
		Description: "List the CISA Known Exploited Vulnerabilities (KEV) catalog",
		Stability:   vgi.StabilityVolatile,
		Categories:  []string{"cve", "kev", "exploit"},
		Examples:    examples,
		Tags: withExamples(withResultSchema(
			"CISA Known Exploited Vulnerabilities",
			"List every entry of the CISA Known Exploited Vulnerabilities (KEV) catalog: CVEs with "+
				"reliable evidence of active exploitation in the wild. Each row carries the CVE id, "+
				"vendor/project, product, vulnerability name, date added, description, required "+
				"remediation action, federal due date, known ransomware-campaign use, notes, and CWEs. "+
				"Join on cve_id to flag which of your CVEs are actively exploited — the strongest "+
				"single signal for patch prioritization. The feed is fetched live (cached in-process "+
				"for 15 minutes).",
			"The full CISA KEV catalog of actively exploited CVEs, read with `kev()`; join on "+
				"`cve_id` to flag exploited CVEs.",
			`["kev","cisa","known exploited vulnerabilities","exploited","actively exploited","in the wild","ransomware","bod 22-01","patch prioritization","vulnerability management","catalog"]`,
			"Exploit Intelligence",
			kevColumns,
		), examples),
	}
}

func (f *KEVFunction) ArgumentSpecs() []vgi.ArgSpec { return vgi.DeriveArgSpecs(kevArgs{}) }

func (f *KEVFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(kevSchema)
}

func (f *KEVFunction) NewState(params *vgi.ProcessParams) (*kevState, error) {
	var args kevArgs
	if err := vgi.BindArgs(params.Args, &args); err != nil {
		return nil, err
	}
	rows, err := FetchKEV(context.Background(), args.BaseURL)
	if err != nil {
		return nil, err
	}
	return &kevState{Rows: rows}, nil
}

func (f *KEVFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *kevState, out *vgirpc.OutputCollector) error {
	return processKEV(state, out)
}

// NewKEVFunction builds the registerable table function.
func NewKEVFunction() vgi.TableFunction {
	return vgi.AsTableFunction[kevState](&KEVFunction{})
}

// ---------------------------------------------------------------------------
// kev_cve(cve_id) -> the KEV entry for one CVE (0 or 1 rows)
// ---------------------------------------------------------------------------

type kevCVEArgs struct {
	CVEID   string `vgi:"pos=0,doc=CVE identifier to check against the KEV catalog (e.g. CVE-2021-44228)"`
	BaseURL string `vgi:"name=base_url,default=,doc=Override the CISA KEV JSON feed URL (the whole URL)"`
}

// KEVCVEFunction returns the KEV entry for a single CVE, or no rows.
type KEVCVEFunction struct{}

var _ vgi.TypedTableFunc[kevState] = (*KEVCVEFunction)(nil)

func (f *KEVCVEFunction) Name() string { return "kev_cve" }

func (f *KEVCVEFunction) Metadata() vgi.FunctionMetadata {
	examples := []vgi.CatalogExample{
		{
			SQL: "SELECT cve_id, vulnerability_name, date_added, due_date, known_ransomware_campaign_use " +
				"FROM cve.main.kev_cve('CVE-2021-44228');",
			Description: "Check whether Log4Shell is in the CISA KEV catalog and show when it was added and its due date.",
		},
		{
			SQL:         "SELECT count(*) > 0 AS is_known_exploited FROM cve.main.kev_cve('CVE-2021-44228');",
			Description: "Answer yes/no: is CVE-2021-44228 a known exploited vulnerability?",
		},
	}
	return vgi.FunctionMetadata{
		Description: "Look up one CVE in the CISA KEV catalog (one row if listed, else none)",
		Stability:   vgi.StabilityVolatile,
		Categories:  []string{"cve", "kev", "exploit"},
		Examples:    examples,
		Tags: withExamples(withResultSchema(
			"KEV Entry for a CVE",
			"Check a single CVE identifier against the CISA Known Exploited Vulnerabilities (KEV) "+
				"catalog. Returns one row with the KEV entry (vendor, product, date added, required "+
				"action, due date, ransomware use, CWEs) when CISA lists the CVE as actively exploited, "+
				"and no rows otherwise — so `count(*) > 0` is an is-exploited test. Matching is "+
				"case-insensitive.",
			"Look up one CVE in the CISA KEV catalog, e.g. `kev_cve('CVE-2021-44228')`; zero rows means "+
				"not known exploited.",
			`["kev","cisa","is exploited","known exploited","kev lookup","exploited cve","ransomware","patch priority","cve check"]`,
			"Exploit Intelligence",
			kevColumns,
		), examples),
	}
}

func (f *KEVCVEFunction) ArgumentSpecs() []vgi.ArgSpec { return vgi.DeriveArgSpecs(kevCVEArgs{}) }

func (f *KEVCVEFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(kevSchema)
}

func (f *KEVCVEFunction) NewState(params *vgi.ProcessParams) (*kevState, error) {
	var args kevCVEArgs
	if err := vgi.BindArgs(params.Args, &args); err != nil {
		return nil, err
	}
	if isNullArg(params.Args, 0) {
		return &kevState{}, nil
	}
	rows, err := FetchKEV(context.Background(), args.BaseURL)
	if err != nil {
		return nil, err
	}
	want := strings.TrimSpace(args.CVEID)
	for _, r := range rows {
		if strings.EqualFold(r.CVEID, want) {
			return &kevState{Rows: []KEVRow{r}}, nil
		}
	}
	return &kevState{}, nil
}

func (f *KEVCVEFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *kevState, out *vgirpc.OutputCollector) error {
	return processKEV(state, out)
}

// NewKEVCVEFunction builds the registerable table function.
func NewKEVCVEFunction() vgi.TableFunction {
	return vgi.AsTableFunction[kevState](&KEVCVEFunction{})
}
