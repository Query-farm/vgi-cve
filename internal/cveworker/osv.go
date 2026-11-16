// Copyright 2026 Query Farm LLC - https://query.farm

package cveworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-rpc-go/vgirpc"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
)

// DefaultOSVURL is the OSV.dev API root (version prefix included). osv_query
// POSTs to <base_url>/query and osv_vuln GETs <base_url>/vulns/<id>; both
// accept a base_url named option (the E2E points it at the mock).
const DefaultOSVURL = "https://api.osv.dev/v1"

// MaxOSVResults bounds how many vulnerabilities osv_query collects across
// next_page_token pages, so a huge package (e.g. the Linux kernel) cannot run
// unbounded.
const MaxOSVResults = 1000

// OSVRow is one OSV vulnerability record, flattened for SQL. Exported +
// gob-encodable (table-function state). Empty strings surface as SQL NULL for
// the optional fields (CVSSVector, DatabaseSeverity, Withdrawn).
type OSVRow struct {
	ID               string
	Summary          string
	Details          string
	Aliases          []string
	CVEIDs           []string
	CVSSVector       string
	DatabaseSeverity string
	Published        string
	Modified         string
	Withdrawn        string
	AffectedPackages []string
	AffectedRanges   []string
	FixedVersions    []string
}

type osvVuln struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
				Limit        string `json:"limit"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

type osvQueryResponse struct {
	Vulns         []osvVuln `json:"vulns"`
	NextPageToken string    `json:"next_page_token"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
}

type osvQueryRequest struct {
	Package   osvPackage `json:"package"`
	Version   string     `json:"version,omitempty"`
	PageToken string     `json:"page_token,omitempty"`
}

// projectOSV flattens a record. When pkgEco/pkgName are set (osv_query), the
// affected ranges and fixed versions are restricted to that package's entries.
func projectOSV(v osvVuln, pkgEco, pkgName string) OSVRow {
	row := OSVRow{
		ID:               v.ID,
		Summary:          v.Summary,
		Details:          v.Details,
		Aliases:          nonNil(v.Aliases),
		Published:        v.Published,
		Modified:         v.Modified,
		Withdrawn:        v.Withdrawn,
		DatabaseSeverity: strings.ToUpper(v.DatabaseSpecific.Severity),
	}
	cves := []string{}
	if strings.HasPrefix(strings.ToUpper(v.ID), "CVE-") {
		cves = append(cves, v.ID)
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") && !contains(cves, a) {
			cves = append(cves, a)
		}
	}
	row.CVEIDs = cves
	row.CVSSVector = pickCVSSVector(v)

	pkgs, ranges, fixed := []string{}, []string{}, []string{}
	for _, a := range v.Affected {
		p := a.Package.Ecosystem + ":" + a.Package.Name
		if a.Package.Name != "" && !contains(pkgs, p) {
			pkgs = append(pkgs, p)
		}
		if pkgName != "" && (!strings.EqualFold(a.Package.Ecosystem, pkgEco) || a.Package.Name != pkgName) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue // commit-hash ranges are noise next to version ranges
			}
			lower := ""
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					lower = e.Introduced
				case e.Fixed != "":
					ranges = appendUnique(ranges, rangeString(lower, "<"+e.Fixed))
					fixed = appendUnique(fixed, e.Fixed)
					lower = ""
				case e.LastAffected != "":
					ranges = appendUnique(ranges, rangeString(lower, "<="+e.LastAffected))
					lower = ""
				case e.Limit != "":
					ranges = appendUnique(ranges, rangeString(lower, "<"+e.Limit))
					lower = ""
				}
			}
			if lower != "" {
				ranges = appendUnique(ranges, rangeString(lower, ""))
			}
		}
	}
	row.AffectedPackages, row.AffectedRanges, row.FixedVersions = pkgs, ranges, fixed
	return row
}

// rangeString renders one affected interval, e.g. ">=2.13.0 <2.15.0"; an
// introduced of "0" (all earlier versions) drops the lower bound.
func rangeString(introduced, upper string) string {
	lo := ""
	if introduced != "" && introduced != "0" {
		lo = ">=" + introduced
	}
	switch {
	case lo == "" && upper == "":
		return "*"
	case lo == "":
		return upper
	case upper == "":
		return lo
	}
	return lo + " " + upper
}

// pickCVSSVector prefers a CVSS v3.x vector (which cvss_base_score accepts),
// then v4, then v2.
func pickCVSSVector(v osvVuln) string {
	for _, want := range []string{"CVSS_V3", "CVSS_V4", "CVSS_V2"} {
		for _, s := range v.Severity {
			if s.Type == want && s.Score != "" {
				return s.Score
			}
		}
	}
	return ""
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func appendUnique(s []string, v string) []string {
	if contains(s, v) {
		return s
	}
	return append(s, v)
}

func osvBase(baseURL string) string {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultOSVURL
	}
	return strings.TrimRight(baseURL, "/")
}

// QueryOSV lists the vulnerabilities OSV.dev records for a package
// (ecosystem + name), optionally narrowed to one version, following
// next_page_token up to MaxOSVResults. Rows are ordered by id.
func QueryOSV(ctx context.Context, baseURL, ecosystem, name, version string) ([]OSVRow, error) {
	ecosystem, name, version = strings.TrimSpace(ecosystem), strings.TrimSpace(name), strings.TrimSpace(version)
	if ecosystem == "" || name == "" {
		return nil, fmt.Errorf("osv: ecosystem and name are both required (e.g. 'PyPI', 'jinja2')")
	}
	hc := &http.Client{Timeout: defaultTimeout}
	endpoint := osvBase(baseURL) + "/query"
	var rows []OSVRow
	token := ""
	for page := 0; page < 100; page++ {
		reqBody, err := json.Marshal(osvQueryRequest{
			Package:   osvPackage{Ecosystem: ecosystem, Name: name},
			Version:   version,
			PageToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("osv: encode request: %w", err)
		}
		body, err := doJSON(ctx, hc, "osv", http.MethodPost, endpoint, reqBody)
		if err != nil {
			return nil, err
		}
		var resp osvQueryResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("osv: decode JSON response: %w", err)
		}
		for _, v := range resp.Vulns {
			rows = append(rows, projectOSV(v, ecosystem, name))
			if len(rows) >= MaxOSVResults {
				break
			}
		}
		token = resp.NextPageToken
		if token == "" || len(rows) >= MaxOSVResults {
			break
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}

// FetchOSVVuln fetches one OSV record by id (GHSA-, CVE-, PYSEC-, GO-, RUSTSEC-
// ...). An unknown id returns (nil, nil).
func FetchOSVVuln(ctx context.Context, baseURL, id string) (*OSVRow, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, nil
	}
	hc := &http.Client{Timeout: defaultTimeout}
	body, err := doJSON(ctx, hc, "osv", http.MethodGet, osvBase(baseURL)+"/vulns/"+url.PathEscape(id), nil)
	if err != nil {
		var nf *errNotFound
		if errors.As(err, &nf) {
			return nil, nil
		}
		return nil, err
	}
	var v osvVuln
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("osv: decode JSON response: %w", err)
	}
	row := projectOSV(v, "", "")
	return &row, nil
}

var osvSchema = arrow.NewSchema([]arrow.Field{
	{Name: "id", Type: arrow.BinaryTypes.String},
	{Name: "summary", Type: arrow.BinaryTypes.String, Nullable: true},
	{Name: "details", Type: arrow.BinaryTypes.String, Nullable: true},
	{Name: "aliases", Type: stringListType},
	{Name: "cve_ids", Type: stringListType},
	{Name: "cvss_vector", Type: arrow.BinaryTypes.String, Nullable: true},
	{Name: "database_severity", Type: arrow.BinaryTypes.String, Nullable: true},
	{Name: "published", Type: arrow.BinaryTypes.String, Nullable: true},
	{Name: "modified", Type: arrow.BinaryTypes.String, Nullable: true},
	{Name: "withdrawn", Type: arrow.BinaryTypes.String, Nullable: true},
	{Name: "affected_packages", Type: stringListType},
	{Name: "affected_ranges", Type: stringListType},
	{Name: "fixed_versions", Type: stringListType},
}, nil)

func osvColumns(rangesScope string) []resultColumn {
	return []resultColumn{
		{"id", "VARCHAR", "OSV identifier of the record, e.g. GHSA-jfh8-c2jp-5v3q, PYSEC-2019-217, or CVE-2021-44228."},
		{"summary", "VARCHAR", "One-line summary; NULL when the source database gives none."},
		{"details", "VARCHAR", "Full Markdown description; NULL when the source database gives none."},
		{"aliases", "VARCHAR[]", "Other identifiers for the same vulnerability (CVE, GHSA, PYSEC, ...)."},
		{"cve_ids", "VARCHAR[]", "The CVE identifiers among id and aliases — join these to cve()/kev()/epss()."},
		{"cvss_vector", "VARCHAR", "CVSS vector string (v3.x preferred so cvss_base_score can score it, else v4, else v2); NULL when unscored."},
		{"database_severity", "VARCHAR", "Source database's qualitative severity (e.g. GHSA's LOW/MODERATE/HIGH/CRITICAL); NULL when absent."},
		{"published", "VARCHAR", "Publication timestamp (RFC 3339)."},
		{"modified", "VARCHAR", "Last-modified timestamp (RFC 3339)."},
		{"withdrawn", "VARCHAR", "Withdrawal timestamp (RFC 3339) when the advisory was retracted; NULL otherwise."},
		{"affected_packages", "VARCHAR[]", "Affected packages as 'ecosystem:name' strings, e.g. 'PyPI:jinja2'."},
		{"affected_ranges", "VARCHAR[]", "Affected version intervals " + rangesScope + ", e.g. '>=2.13.0 <2.15.0' or '<2.10.1' (git commit ranges omitted)."},
		{"fixed_versions", "VARCHAR[]", "Versions that fix the vulnerability " + rangesScope + "."},
	}
}

type osvState struct {
	Rows   []OSVRow
	Offset int
}

func processOSV(state *osvState, out *vgirpc.OutputCollector) error {
	r, done := nextRows(state.Rows, &state.Offset)
	if done {
		return out.Finish()
	}
	n := len(r)
	n64 := int64(n)
	batch := array.NewRecordBatch(osvSchema, []arrow.Array{
		vgi.BuildStringArray(n64, func(i int64) string { return r[i].ID }),
		buildNullableString(n, func(i int) string { return r[i].Summary }),
		buildNullableString(n, func(i int) string { return r[i].Details }),
		buildStringList(n, func(i int) []string { return r[i].Aliases }),
		buildStringList(n, func(i int) []string { return r[i].CVEIDs }),
		buildNullableString(n, func(i int) string { return r[i].CVSSVector }),
		buildNullableString(n, func(i int) string { return r[i].DatabaseSeverity }),
		buildNullableString(n, func(i int) string { return r[i].Published }),
		buildNullableString(n, func(i int) string { return r[i].Modified }),
		buildNullableString(n, func(i int) string { return r[i].Withdrawn }),
		buildStringList(n, func(i int) []string { return r[i].AffectedPackages }),
		buildStringList(n, func(i int) []string { return r[i].AffectedRanges }),
		buildStringList(n, func(i int) []string { return r[i].FixedVersions }),
	}, n64)
	defer batch.Release()
	return out.Emit(batch)
}

// ---------------------------------------------------------------------------
// osv_query(ecosystem, name, version := '') -> vulnerabilities for a package
// ---------------------------------------------------------------------------

type osvQueryArgs struct {
	Ecosystem string `vgi:"pos=0,doc=OSV ecosystem name (e.g. PyPI / npm / Maven / Go / crates.io / RubyGems / NuGet / Packagist)"`
	Name      string `vgi:"pos=1,doc=Package name as the ecosystem spells it (e.g. jinja2 or org.apache.logging.log4j:log4j-core)"`
	Version   string `vgi:"name=version,default=,doc=Package version to check; empty returns every known vulnerability of the package"`
	BaseURL   string `vgi:"name=base_url,default=,doc=Override the OSV.dev API root URL (default https://api.osv.dev/v1)"`
}

// OSVQueryFunction lists OSV vulnerabilities for a package (and version).
type OSVQueryFunction struct{}

var _ vgi.TypedTableFunc[osvState] = (*OSVQueryFunction)(nil)

func (f *OSVQueryFunction) Name() string { return "osv_query" }

func (f *OSVQueryFunction) Metadata() vgi.FunctionMetadata {
	examples := []vgi.CatalogExample{
		{
			SQL: "SELECT id, cve_ids, database_severity, fixed_versions " +
				"FROM cve.main.osv_query('PyPI', 'jinja2', version := '2.4.1') ORDER BY id;",
			Description: "List the OSV advisories affecting jinja2 2.4.1 with their CVE ids and fixed versions.",
		},
		ExampleOSVPackageInKEV,
	}
	return vgi.FunctionMetadata{
		Description: "List OSV.dev vulnerabilities affecting an open-source package (optionally one version)",
		Stability:   vgi.StabilityVolatile,
		Categories:  []string{"cve", "osv", "open source"},
		Examples:    examples,
		Tags: withExamples(withResultSchema(
			"OSV Package Vulnerabilities",
			"Query OSV.dev, the distributed open-source vulnerability database (GitHub Security "+
				"Advisories, PyPI, Go, RustSec, npm, Maven, OSS-Fuzz and more), for the vulnerabilities "+
				"affecting a package given its ecosystem and name, optionally narrowed with version := "+
				"'x.y.z' to the advisories that affect exactly that version. Each row carries the OSV "+
				"id, summary, details, aliases, the CVE ids among them, a CVSS vector, the source "+
				"database severity, timestamps, and that package's affected version ranges and fixed "+
				"versions. Paged via next_page_token and bounded to 1000 rows. OSV data is CC-BY-4.0.",
			"Vulnerabilities OSV.dev records for a package, e.g. "+
				"`osv_query('PyPI', 'jinja2', version := '2.4.1')`.",
			`["osv","osv.dev","open source vulnerabilities","package vulnerabilities","dependency scanning","sca","ghsa","github advisory","pypi","npm","maven","go","crates.io","fixed version"]`,
			"Open Source Vulnerabilities",
			osvColumns("for the queried package"),
		), examples),
	}
}

func (f *OSVQueryFunction) ArgumentSpecs() []vgi.ArgSpec { return vgi.DeriveArgSpecs(osvQueryArgs{}) }

func (f *OSVQueryFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(osvSchema)
}

func (f *OSVQueryFunction) NewState(params *vgi.ProcessParams) (*osvState, error) {
	var args osvQueryArgs
	if err := vgi.BindArgs(params.Args, &args); err != nil {
		return nil, err
	}
	if isNullArg(params.Args, 0) || isNullArg(params.Args, 1) {
		return &osvState{}, nil
	}
	rows, err := QueryOSV(context.Background(), args.BaseURL, args.Ecosystem, args.Name, args.Version)
	if err != nil {
		return nil, err
	}
	return &osvState{Rows: rows}, nil
}

func (f *OSVQueryFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *osvState, out *vgirpc.OutputCollector) error {
	return processOSV(state, out)
}

// NewOSVQueryFunction builds the registerable table function.
func NewOSVQueryFunction() vgi.TableFunction {
	return vgi.AsTableFunction[osvState](&OSVQueryFunction{})
}

// ---------------------------------------------------------------------------
// osv_vuln(id) -> one OSV record (0 or 1 rows)
// ---------------------------------------------------------------------------

type osvVulnArgs struct {
	ID      string `vgi:"pos=0,doc=OSV vulnerability id (e.g. GHSA-jfh8-c2jp-5v3q / PYSEC-2019-217 / CVE-2021-44228)"`
	BaseURL string `vgi:"name=base_url,default=,doc=Override the OSV.dev API root URL (default https://api.osv.dev/v1)"`
}

// OSVVulnFunction fetches one OSV record by id.
type OSVVulnFunction struct{}

var _ vgi.TypedTableFunc[osvState] = (*OSVVulnFunction)(nil)

func (f *OSVVulnFunction) Name() string { return "osv_vuln" }

func (f *OSVVulnFunction) Metadata() vgi.FunctionMetadata {
	examples := []vgi.CatalogExample{
		{
			SQL: "SELECT id, summary, cve_ids, cvss_vector, affected_packages, fixed_versions " +
				"FROM cve.main.osv_vuln('GHSA-jfh8-c2jp-5v3q');",
			Description: "Fetch the GitHub advisory for Log4Shell from OSV.dev with its CVE id, CVSS vector, and fixed versions.",
		},
		{
			SQL: "SELECT id, cvss_vector, cve.main.cvss_base_score(cvss_vector) AS base_score " +
				"FROM cve.main.osv_vuln('GHSA-462w-v97r-4m45');",
			Description: "Score the CVSS v3 vector OSV.dev records for a jinja2 sandbox-escape advisory offline.",
		},
	}
	return vgi.FunctionMetadata{
		Description: "Fetch one OSV.dev vulnerability record by id (GHSA-, PYSEC-, CVE-, GO-, RUSTSEC- ...)",
		Stability:   vgi.StabilityVolatile,
		Categories:  []string{"cve", "osv", "open source"},
		Examples:    examples,
		Tags: withExamples(withResultSchema(
			"OSV Vulnerability by ID",
			"Fetch a single OSV.dev vulnerability record by its identifier — a GitHub Security "+
				"Advisory (GHSA-...), PyPI (PYSEC-...), Go (GO-...), RustSec (RUSTSEC-...), CVE "+
				"(CVE-...) or any other OSV id — returning its summary, details, aliases and CVE ids, "+
				"CVSS vector, source severity, timestamps, every affected package, and the affected "+
				"version ranges and fixed versions across all of them. Returns no rows for an unknown "+
				"id. OSV data is CC-BY-4.0.",
			"Fetch one OSV.dev record by id, e.g. `osv_vuln('GHSA-jfh8-c2jp-5v3q')`; unknown ids return "+
				"no rows.",
			`["osv","osv.dev","ghsa","github security advisory","pysec","rustsec","go vulndb","advisory lookup","vulnerability by id","fixed version","aliases"]`,
			"Open Source Vulnerabilities",
			osvColumns("across all affected packages"),
		), examples),
	}
}

func (f *OSVVulnFunction) ArgumentSpecs() []vgi.ArgSpec { return vgi.DeriveArgSpecs(osvVulnArgs{}) }

func (f *OSVVulnFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(osvSchema)
}

func (f *OSVVulnFunction) NewState(params *vgi.ProcessParams) (*osvState, error) {
	var args osvVulnArgs
	if err := vgi.BindArgs(params.Args, &args); err != nil {
		return nil, err
	}
	if isNullArg(params.Args, 0) {
		return &osvState{}, nil
	}
	row, err := FetchOSVVuln(context.Background(), args.BaseURL, args.ID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return &osvState{}, nil
	}
	return &osvState{Rows: []OSVRow{*row}}, nil
}

func (f *OSVVulnFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *osvState, out *vgirpc.OutputCollector) error {
	return processOSV(state, out)
}

// NewOSVVulnFunction builds the registerable table function.
func NewOSVVulnFunction() vgi.TableFunction {
	return vgi.AsTableFunction[osvState](&OSVVulnFunction{})
}
