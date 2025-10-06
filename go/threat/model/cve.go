package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/k3a/html2text"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
)

type (
	CVE struct {
		ID                 string           `json:"id"`
		Name               string           `json:"name"`
		Created            int64            `json:"created"`
		Modified           int64            `json:"modified"`
		Latest             int64            `json:"latest"`
		Published          int64            `json:"published"`
		Crawled            int64            `json:"crawled"`
		Vendor             []string         `json:"vendor"`
		Affect             int64            `json:"affect"`
		Customer           []string         `json:"customer"`
		Match              []string         `json:"match"`
		Status             int              `json:"status"`
		Score              CVEScore         `json:"score"`
		EPSS               EPSSMetric       `json:"epss"`
		CWE                []CWEMetric      `json:"cwe"`
		Checker            string           `json:"checker"`
		Checklist          CVEChecklist     `json:"checklist"`
		Languages          []string         `json:"languages"`
		Searchable         CVESearchable    `json:"searchable"`
		Approved           int64            `json:"approved"`
		AnalysisTime       int64            `json:"analysis_time"`
		ApprovedFirst      int64            `json:"approved_first"`
		CPEDetails         []CPEMatchDetail `json:"cpe_details"`
		CPENodes           []CVENode        `json:"cpe_nodes"`
		History            []SeverityMetric `json:"history"`
		ProductType        []string         `json:"product_type"`
		ReportLink         []string         `json:"report_link"`
		InternalFlag       []string         `json:"internal_flag"`
		Creator            string           `json:"creator"`
		AnalyzedTime       int64            `json:"analyzed_time"`
		Organizations      []Organization   `json:"organizations"`
		OldStatus          int              `json:"old_status"`
		ReasonChangeStatus string           `json:"reason_change_status"`
		Source             string           `json:"source"`
	}

	Organization struct {
		ApprovalTime int64  `json:"approval_time"`
		TenantId     string `json:"tenant_id"`
	}

	CPEMatchDetail struct {
		CPE                   string `json:"cpe"`
		VersionStartIncluding string `json:"version_start_including"`
		VersionEndIncluding   string `json:"version_end_including"`
		VersionStartExcluding string `json:"version_start_excluding"`
		VersionEndExcluding   string `json:"version_end_excluding"`
	}

	CVELang struct {
		ID          string   `json:"id"`
		Lang        string   `json:"lang"`
		Description string   `json:"description"`
		Raw         string   `json:"raw"`
		Reference   []string `json:"reference"`
		Patch       []string `json:"patch"`
	}

	CVESearchable struct {
		EN CVESearch `json:"en"`
		VI CVESearch `json:"vi"`
	}

	CVESearch struct {
		Description string   `json:"description"`
		Reference   []string `json:"reference"`
	}

	CVEDelivery struct {
		CVE
		Delivery bool `json:"delivery"`
	}

	CVEVerbose struct {
		CVE
		MultiLang     Language               `json:"multilang"`
		Products      []*CPEDetail           `json:"products"`
		Clients       []*GroupUser           `json:"clients"`
		CVSS          map[string]interface{} `json:"cvss"`
		ThreatReports []*ThreatReport        `json:"threat_reports"`
	}

	ThreatReport struct {
		ApprovedTime int64       `json:"approved_time"`
		CodeReport   string      `json:"code_report"`
		ReportName   TitleReport `json:"name"`
	}

	TitleReport struct {
		Vi string `json:"vi"`
		En string `json:"en"`
	}

	CVSSMetric struct {
		CVSS2 CVEMetric `json:"cvss_v2"`
		CVSS3 CVEMetric `json:"cvss_v3"`
		CVSS4 CVEMetric `json:"cvss_v4"`
		CNA   CVEMetric `json:"cna"`
	}

	CVEScore struct {
		Global CVEMetric `json:"global"`
		VTI    CVEMetric `json:"vti"`
		CVSSMetric
	}

	EPSSMetric struct {
		Score      *float64 `json:"score"`
		Percentile *float64 `json:"percentile"`
	}

	CWEMetric struct {
		ID   string `json:"id" validate:"required"`
		Name string `json:"name"`
		Link string `json:"link" validate:"required"`
	}

	CVEChecklist struct {
		Metric CVECheckListMetric `json:"metric"`
		Point  int                `json:"point"`
	}

	CVECheckListMetric struct {
		Affect    int `json:"affect"`
		Exploit   int `json:"exploit"`
		Patch     int `json:"patch"`
		Ability   int `json:"ability"`
		Condition int `json:"condition"`
	}

	CVEMetric struct {
		Score        float32 `json:"score"`
		Version      string  `json:"version"`
		Severity     int     `json:"severity"`
		VectorString string  `json:"vector_string"`
		Source       string  `json:"source"`
	}

	SeverityMetric struct {
		Created  int64  `json:"created"`
		Severity int    `json:"severity"`
		Type     string `json:"type"`
	}

	CVEConfigurations struct {
		DataVersion string    `json:"CVE_data_version"`
		Nodes       []CVENode `json:"nodes"`
	}

	CVEImpact struct {
		MetricV4 CvssV4 `json:"baseMetricV4"`
		MetricV3 CvssV3 `json:"baseMetricV3"`
		MetricV2 CvssV2 `json:"baseMetricV2"`
	}

	CVENode struct {
		Operator string     `json:"operator"`
		Children []CVENode  `json:"children"`
		Match    []CPEMatch `json:"cpe_match"`
	}

	CPEMatch struct {
		Vulnerable            bool   `json:"vulnerable"`
		Cpe23Uri              string `json:"cpe23Uri"`
		VersionStartIncluding string `json:"versionStartIncluding"`
		VersionEndIncluding   string `json:"versionEndIncluding"`
	}

	CVEDetail struct {
		DataType    string         `json:"data_type"`
		DataFormat  string         `json:"data_format"`
		DataVersion string         `json:"data_version"`
		Metadata    CVEMetadata    `json:"CVE_data_meta"`
		ProblemType CVEProblemType `json:"problemtype"`
		References  CVEReference   `json:"references"`
		Description CVEDescription `json:"description"`
	}

	CVEMetadata struct {
		ID       string `json:"ID"`
		Assigner string `json:"ASSIGNER"`
	}

	CVEProblemType struct {
		Data []CVEProblemTypeData `json:"problemtype_data"`
	}

	CVEReference struct {
		Data []CVEReferenceData `json:"reference_data"`
	}

	CVEDescriptionData struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}

	CVEDescription struct {
		Data []CVEDescriptionData `json:"description_data"`
	}

	CVEProblemTypeData struct {
		Description []CVEDescriptionData `json:"description"`
	}

	CVEReferenceData struct {
		Url       string   `json:"url"`
		Name      string   `json:"name"`
		Refsource string   `json:"refsource"`
		Tags      []string `json:"tags"`
	}

	CVERaw struct {
		Detail           CVEDetail         `json:"cve"`
		Configurations   CVEConfigurations `json:"configurations"`
		Impact           CVEImpact         `json:"impact"`
		PublishedDate    string            `json:"publishedDate"`
		LastModifiedDate string            `json:"lastModifiedDate"`
	}

	CVEJobLanguage struct {
		WG      *sync.WaitGroup
		Index   int
		Results []*CVEVerbose
	}
	// Request
	RequestCVESearch struct {
		Keyword      string             `json:"keyword"`
		CVEName      string             `json:"cve_name"`
		Checker      string             `json:"checker"`
		InternalFlag []string           `json:"internal_flag"`
		Source       []string           `json:"source"`
		Customers    []string           `json:"customers"`
		Severity     RequestCVESeverity `json:"severity"`
		Status       []int              `json:"status"`
		Languages    []string           `json:"languages"`
		Time         CVESearchTime      `json:"time"`
		Sort         []string           `json:"sort"`
		Size         int                `json:"size" validate:"numeric,gte=0"`
		Offset       int                `json:"offset" validate:"numeric,gte=0"`
	}

	RequestLifeCycleCVE struct {
		ReportCode    string   `json:"report_code"`
		CVECode       []string `json:"cve_code"`
		DetectionTime int64    `json:"detection_time"`
	}

	CVESearchTime struct {
		Approved     RangeInt64 `json:"approved"`
		Modified     RangeInt64 `json:"modified"`
		AnalysisTime RangeInt64 `json:"analysis_time"`
	}

	RequestExport struct {
		Ids []string         `json:"ids"`
		Req RequestCVESearch `json:"req"`
	}

	RequestCVESeverity struct {
		VTI    RequestCVESeverityVerbose   `json:"vti"`
		Global RequestCVESeverityVerboseV2 `json:"global"`
	}

	RequestCVESeverityVerbose struct {
		Version string `json:"version"`
		Value   []int  `json:"value"`
	}

	RequestCVESeverityVerboseV2 struct {
		Version            []string `json:"version"`
		SeverityVersion2   []int    `json:"severity_version_2"`
		SeverityVersion3   []int    `json:"severity_version_3"`
		SeverityVersion4   []int    `json:"severity_version_4"`
		SeverityVersionCNA []int    `json:"severity_version_cna"`
	}

	RequestCVEID struct {
		ID string `json:"id" param:"id" validate:"required"`
	}

	RequestCVECreate struct {
		ID          string                   `json:"id" param:"id" validate:"required"`
		Published   int64                    `json:"published"`
		Match       []string                 `json:"match"`
		Product     RequestCPESuggestProduct `json:"product"`
		Description string                   `json:"description"`
		Reference   string                   `json:"reference"`
		Patch       string                   `json:"patch"`
		CVSS        CVSSMetric               `json:"cvss"`
		EPSS        *EPSSMetric              `json:"epss"`
		CWE         []CWEMetric              `json:"cwe" validate:"dive"`
		Lang        string                   `json:"lang" validate:"required"`
	}

	RequestCVEEdit struct {
		ID          string                   `json:"id" param:"id" validate:"required"`
		Published   int64                    `json:"published"`
		Match       []string                 `json:"match"`
		Product     RequestCPESuggestProduct `json:"product"`
		Description string                   `json:"description"`
		Reference   string                   `json:"reference"`
		Patch       string                   `json:"patch"`
		CVSS        CVSSMetric               `json:"cvss"`
		EPSS        *EPSSMetric              `json:"epss"`
		CWE         []CWEMetric              `json:"cwe" validate:"dive"`
		Lang        string                   `json:"lang" validate:"required"`
	}

	RequestCVEConfirm struct {
		ID          string       `json:"id" param:"id"`
		Status      int          `json:"status"`
		Checklist   CVEChecklist `json:"checklist"`
		Description string       `json:"description"`
	}

	CreateLifecycleRequest struct {
		ID     string             `json:"id" param:"id" validate:"required"`
		Event  CVELifecycleEvent  `json:"event" validate:"required"`
		Source CVELifecycleSource `json:"source" validate:"required"`
		Title  string             `json:"title"`
	}

	RequestCVEStatistic struct {
		Checker       string   `json:"checker"`
		InternalFlags []string `json:"internal_flags"`
	}

	RequestCVECommon struct {
		IDs    []string         `json:"ids"`
		Filter RequestCVESearch `json:"filter"`
	}

	RequestCVEsReject struct {
		RequestCVECommon
		Status      int    `json:"status"`
		Description string `json:"description"`
	}

	RequestCVEsInternalFlag struct {
		RequestCVECommon
		Action    int      `json:"action"`
		FlagsName []string `json:"flags_name"`
	}
)

func (doc *CVEMetric) SetVTIMetric() {
	switch doc.Version {
	case defs.VersionVcs10:
		if doc.Score < 4 {
			doc.Severity = defs.SeverityCodeUnknown
		} else if doc.Score >= 4 && doc.Score < 8 {
			doc.Severity = defs.SeverityCodeLow
		} else if doc.Score >= 8 && doc.Score < 11 {
			doc.Severity = defs.SeverityCodeMedium
		} else if doc.Score >= 11 && doc.Score < 13 {
			doc.Severity = defs.SeverityCodeHigh
		} else {
			doc.Severity = defs.SeverityCodeCritical
		}
	}
}

func (doc *CVE) GetID() string {
	// Success
	return doc.ID
}

func (doc *CVE) SetEID(id string) {
	// Success
	doc.ID = id
}

func (doc *CVE) GetVendor() []string {
	vendors := make([]string, 0)
	for _, product := range doc.Match {
		cpe := strings.Split(product, ":")
		if len(cpe) >= 4 {
			vendor := strings.Title(cpe[3])
			if !slice.String(vendors).Contains(vendor) {
				vendors = append(vendors, vendor)
			}
		}
	}
	// Success
	return vendors
}

// GetLatestCVSSMetric returns the latest CVSS metric from the CVE object.
// The latest metric is determined by the order of CVSS4, CVSS3, CVSS2.
// If none of the metrics are specified, it returns an empty CVEMetric object.
func (doc *CVE) GetLatestCVSSMetric() CVEMetric {
	if doc.Score.CVSS4.Version != "" {
		return doc.Score.CVSS4
	}
	if doc.Score.CVSS3.Version != "" {
		return doc.Score.CVSS3
	}
	if doc.Score.CVSS2.Version != "" {
		return doc.Score.CVSS2
	}
	// Success
	return CVEMetric{}
}

func (body *RequestCVECreate) Generate() (*CVE, *CVELang) {
	now, _ := clock.Now(clock.Local)
	timestamp := clock.UnixMilli(now)
	document := &CVE{
		ID:           hash.SHA1(body.ID),
		Name:         body.ID,
		Created:      timestamp,
		Modified:     timestamp,
		Published:    body.Published,
		Crawled:      timestamp,
		AnalysisTime: timestamp,
		Vendor:       nil,
		Customer:     []string{},
		Match:        body.Match,
		Status:       defs.StatusCodeUnknown,
		Score: CVEScore{
			VTI: CVEMetric{
				Version: defs.VersionVcs10,
			},
		},
		EPSS:    *body.EPSS,
		CWE:     body.CWE,
		Checker: defs.DefaultChecker,
		Checklist: CVEChecklist{
			Metric: CVECheckListMetric{
				Affect:    defs.PointNil,
				Exploit:   defs.PointNil,
				Patch:     defs.PointNil,
				Ability:   defs.PointNil,
				Condition: defs.PointNil,
			},
			Point: 0,
		},
		Languages: []string{body.Lang},
		Source:    defs.SourceCve,
		OldStatus: defs.PointNil,
	}
	if body.CVSS.CVSS2.Version != "" || body.CVSS.CVSS3.Version != "" || body.CVSS.CVSS4.Version != "" || body.CVSS.CNA.Version != "" {
		if strings.HasPrefix(body.CVSS.CVSS2.Version, "2.") {
			cvssV2 := CVEMetric{
				Score:        body.CVSS.CVSS2.Score,
				Version:      body.CVSS.CVSS2.Version,
				VectorString: body.CVSS.CVSS2.VectorString,
				Source:       body.CVSS.CVSS2.Source,
			}
			for severity, point := range defs.RangeCvssV2SeverityScore {
				rPoint := point.(map[string]float32)
				if body.CVSS.CVSS2.Score >= rPoint["gte"] && body.CVSS.CVSS2.Score <= rPoint["lte"] {
					cvssV2.Severity = severity
					break
				}
			}
			document.Score.CVSS2 = cvssV2
			document.Score.Global = cvssV2
		}
		if strings.HasPrefix(body.CVSS.CVSS3.Version, "3.") {
			cvssV3 := CVEMetric{
				Score:        body.CVSS.CVSS3.Score,
				Version:      body.CVSS.CVSS3.Version,
				VectorString: body.CVSS.CVSS3.VectorString,
				Source:       body.CVSS.CVSS3.Source,
			}
			for severity, point := range defs.RangeCvssV3SeverityScore {
				rPoint := point.(map[string]float32)
				if body.CVSS.CVSS3.Score >= rPoint["gte"] && body.CVSS.CVSS3.Score <= rPoint["lte"] {
					cvssV3.Severity = severity
					break
				}
			}
			document.Score.CVSS3 = cvssV3
			document.Score.Global = cvssV3
		}
		if strings.HasPrefix(body.CVSS.CVSS4.Version, "4.") {
			cvssV4 := CVEMetric{
				Score:        body.CVSS.CVSS4.Score,
				Version:      body.CVSS.CVSS4.Version,
				VectorString: body.CVSS.CVSS4.VectorString,
				Source:       body.CVSS.CVSS4.Source,
			}
			for severity, point := range defs.RangeCvssV4SeverityScore {
				rPoint := point.(map[string]float32)
				if body.CVSS.CVSS4.Score >= rPoint["gte"] && body.CVSS.CVSS4.Score <= rPoint["lte"] {
					cvssV4.Severity = severity
					break
				}
			}
			document.Score.CVSS4 = cvssV4
			document.Score.Global = cvssV4
		}
		if body.CVSS.CNA.Version != "" {
			cna := ProcessCVSSCNA(
				body.CVSS.CNA.Score,
				body.CVSS.CNA.Version,
				body.CVSS.CNA.VectorString,
				body.CVSS.CNA.Source,
			)
			document.Score.CNA = cna
			if document.Score.CVSS2.Version == "" &&
				document.Score.CVSS3.Version == "" &&
				document.Score.CVSS4.Version == "" {
				document.Score.Global = cna
			}
		}
		if document.Score.CVSS2.Version == "" &&
			document.Score.CVSS3.Version == "" &&
			document.Score.CVSS4.Version == "" &&
			document.Score.CNA.Version == "" {
			document.Score.Global = CVEMetric{}
		}
	}
	description := strings.TrimSpace(html2text.HTML2Text(body.Description))
	switch body.Lang {
	case defs.LangVI:
		document.Searchable.VI.Description = description
		document.Searchable.VI.Reference = strings.Split(body.Reference, "\n")
	case defs.LangEN:
		document.Searchable.EN.Description = description
		document.Searchable.EN.Reference = strings.Split(body.Reference, "\n")
	}
	document.Vendor = document.GetVendor()
	language := &CVELang{
		ID:          document.ID,
		Lang:        body.Lang,
		Description: description,
		Raw:         body.Description,
		Reference:   strings.Split(body.Reference, "\n"),
		Patch:       strings.Split(body.Patch, "\n"),
	}
	return document, language
}

func (body *RequestCVESearch) PrepareQuery() map[string]interface{} {
	filter := make([]interface{}, 0)
	// Keyword
	if body.Keyword != "" {
		wildcard := fmt.Sprintf("*%s*", regexp.QuoteMeta(body.Keyword))
		should := make([]interface{}, 0)
		should = append(should,
			map[string]interface{}{
				"term": map[string]interface{}{
					"vendor": body.Keyword,
				},
			},
			map[string]interface{}{
				"wildcard": map[string]interface{}{
					"name": wildcard,
				},
			},
			map[string]interface{}{
				"wildcard": map[string]interface{}{
					"match": wildcard,
				},
			},
			map[string]interface{}{
				"wildcard": map[string]interface{}{
					"searchable.en.description": wildcard,
				},
			},
			map[string]interface{}{
				"wildcard": map[string]interface{}{
					"searchable.vi.description": wildcard,
				},
			},
		)
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": should,
			},
		})
	}
	// Checker
	if body.Checker != "" {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"checker": body.Checker,
			},
		})
	}
	if body.CVEName != "" {
		wildcard := fmt.Sprintf("*%s*", regexp.QuoteMeta(body.CVEName))
		should := make([]interface{}, 0)
		should = append(should,
			map[string]interface{}{
				"wildcard": map[string]interface{}{
					"name": wildcard,
				},
			},
		)
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": should,
			},
		})
	}
	if len(body.InternalFlag) > 0 {
		filter = append(filter, map[string]interface{}{
			"terms": map[string]interface{}{
				"internal_flag": body.InternalFlag,
			},
		})
	}
	if len(body.Source) > 0 {
		filter = append(filter, map[string]interface{}{
			"terms": map[string]interface{}{
				"source": body.Source,
			},
		})
	}
	// Customer
	if len(body.Customers) > 0 {
		filter = append(filter, map[string]interface{}{
			"terms": map[string]interface{}{
				"customer": body.Customers,
			},
		})
	}
	// Severity
	if body.Severity.VTI.Version != "" {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"score.vti.version": body.Severity.VTI.Version,
			},
		})
	}
	if len(body.Severity.VTI.Value) > 0 {
		filter = append(filter, map[string]interface{}{
			"terms": map[string]interface{}{
				"score.vti.severity": body.Severity.VTI.Value,
			},
		})
	}
	if len(body.Severity.Global.Version) > 0 {
		should := make([]interface{}, 0)
		for _, version := range body.Severity.Global.Version {
			switch version {
			case defs.VersionCvssV2:
				filterVersion := make([]interface{}, 0)
				filterVersion = append(filterVersion, map[string]interface{}{
					"wildcard": map[string]interface{}{
						"score.cvss_v2.version": "2.*",
					},
				})
				if len(body.Severity.Global.SeverityVersion2) > 0 {
					filterVersion = append(filterVersion, map[string]interface{}{
						"terms": map[string]interface{}{
							"score.cvss_v2.severity": body.Severity.Global.SeverityVersion2,
						},
					})
				}
				should = append(should, map[string]interface{}{
					"bool": map[string]interface{}{
						"filter": filterVersion,
					},
				})
			case defs.VersionCvssV3:
				filterVersion := make([]interface{}, 0)
				filterVersion = append(filterVersion, map[string]interface{}{
					"wildcard": map[string]interface{}{
						"score.cvss_v3.version": defs.VersionCvssV3,
					},
				})
				if len(body.Severity.Global.SeverityVersion3) > 0 {
					filterVersion = append(filterVersion, map[string]interface{}{
						"terms": map[string]interface{}{
							"score.cvss_v3.severity": body.Severity.Global.SeverityVersion3,
						},
					})
				}
				should = append(should, map[string]interface{}{
					"bool": map[string]interface{}{
						"filter": filterVersion,
					},
				})
			case defs.VersionCvssV4:
				filterVersion := make([]interface{}, 0)
				filterVersion = append(filterVersion, map[string]interface{}{
					"wildcard": map[string]interface{}{
						"score.cvss_v4.version": defs.VersionCvssV4,
					},
				})
				if len(body.Severity.Global.SeverityVersion4) > 0 {
					filterVersion = append(filterVersion, map[string]interface{}{
						"terms": map[string]interface{}{
							"score.cvss_v4.severity": body.Severity.Global.SeverityVersion4,
						},
					})
				}
				should = append(should, map[string]interface{}{
					"bool": map[string]interface{}{
						"filter": filterVersion,
					},
				})
			case defs.VersionCvssCNA:
				filterVersion := make([]interface{}, 0)
				filterVersion = append(filterVersion, map[string]interface{}{
					"exists": map[string]interface{}{
						"field": "score.cna",
					},
				})
				mustNot := map[string]interface{}{
					"term": map[string]interface{}{
						"score.cna.version": "",
					},
				}
				if len(body.Severity.Global.SeverityVersionCNA) > 0 {
					filterVersion = append(filterVersion, map[string]interface{}{
						"terms": map[string]interface{}{
							"score.cna.severity": body.Severity.Global.SeverityVersionCNA,
						},
					})
				}
				should = append(should, map[string]interface{}{
					"bool": map[string]interface{}{
						"filter":   filterVersion,
						"must_not": mustNot,
					},
				})
			default:
				should = append(should, map[string]interface{}{
					"term": map[string]interface{}{
						"score.global.version": "",
					},
				})
			}
		}
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": should,
			},
		})
	}

	// Status
	if body.Status != nil && len(body.Status) > 0 {
		filter = append(filter, map[string]interface{}{
			"terms": map[string]interface{}{
				"status": body.Status,
			},
		})
	}
	// Languages
	if len(body.Languages) > 0 {
		should := make([]interface{}, 0)
		for _, lang := range body.Languages {
			if strings.Contains(lang, defs.LangVI) && strings.Contains(lang, defs.LangEN) {
				should = append(should, map[string]interface{}{
					"bool": map[string]interface{}{
						"filter": []interface{}{
							map[string]interface{}{
								"term": map[string]interface{}{
									"languages": defs.LangVI,
								},
							},
							map[string]interface{}{
								"term": map[string]interface{}{
									"languages": defs.LangEN,
								},
							},
						},
					},
				})
			} else {
				should = append(should, map[string]interface{}{
					"term": map[string]interface{}{
						"languages": lang,
					},
				})
			}
		}
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": should,
			},
		})
		if len(body.Languages) == 1 && !(strings.Contains(body.Languages[0], defs.LangVI) && strings.Contains(body.Languages[0], defs.LangEN)) {
			filter = append(filter, map[string]interface{}{
				"bool": map[string]interface{}{
					"must_not": []interface{}{
						map[string]interface{}{
							"term": map[string]interface{}{
								"languages": defs.EnumLanguage[1-slice.String(defs.EnumLanguage).Index(body.Languages[0])],
							},
						},
					},
				},
			})
		}
	}
	// Time
	createdFilter := map[string]interface{}{}
	if body.Time.Approved.Gte > 0 {
		gte, _ := clock.ParseMilliTimestamp(body.Time.Approved.Gte, clock.Local)
		createdFilter["gte"] = clock.UnixMilli(gte)
	}
	if body.Time.Approved.Lte > 0 {
		lte, _ := clock.ParseMilliTimestamp(body.Time.Approved.Lte, clock.Local)
		createdFilter["lte"] = clock.UnixMilli(lte)
	}
	if len(createdFilter) > 0 {
		filter = append(filter, map[string]interface{}{"range": map[string]interface{}{"approved": createdFilter}})
	}

	createdFilterModified := map[string]interface{}{}
	if body.Time.Modified.Gte > 0 {
		gte, _ := clock.ParseMilliTimestamp(body.Time.Modified.Gte, clock.Local)
		createdFilterModified["gte"] = clock.UnixMilli(gte)
	}
	if body.Time.Modified.Lte > 0 {
		lte, _ := clock.ParseMilliTimestamp(body.Time.Modified.Lte, clock.Local)
		createdFilterModified["lte"] = clock.UnixMilli(lte)
	}
	if len(createdFilterModified) > 0 {
		filter = append(filter, map[string]interface{}{"range": map[string]interface{}{"modified": createdFilterModified}})
	}

	createdFilterAnalysis := map[string]interface{}{}
	if body.Time.AnalysisTime.Gte > 0 {
		gte, _ := clock.ParseMilliTimestamp(body.Time.AnalysisTime.Gte, clock.Local)
		createdFilterAnalysis["gte"] = clock.UnixMilli(gte)
	}
	if body.Time.AnalysisTime.Lte > 0 {
		lte, _ := clock.ParseMilliTimestamp(body.Time.AnalysisTime.Lte, clock.Local)
		createdFilterAnalysis["lte"] = clock.UnixMilli(lte)
	}
	if len(createdFilterAnalysis) > 0 {
		filter = append(filter, map[string]interface{}{"range": map[string]interface{}{"analysis_time": createdFilterAnalysis}})
	}
	// Success
	if len(filter) == 0 {
		return defs.ElasticsearchQueryFilterMatchAll
	}
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": filter,
		},
	}
}

func (body *RequestLifeCycleCVE) PrepareQuery() map[string]interface{} {
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"terms": map[string]interface{}{
						"name": body.CVECode,
					},
				},
			},
		},
	}
}

func (doc *CVELang) GetID() string {
	// Success
	return doc.ID
}

func (doc *CVELang) SetEID(id string) {
	// Success
	doc.ID = id
}

func (doc *CVERaw) GetID() string {
	// Success
	return hash.SHA1(doc.Detail.Metadata.ID)
}

func (doc *CVERaw) SetEID(id string) {
	// Success
}

func (doc *CVERaw) GetLastModified() time.Time {
	modified, err := clock.ParseRFC3339(doc.LastModifiedDate)
	if err == nil {
		modified, _ := clock.InTimezone(modified, clock.Local)
		return modified
	} else {
		return time.Time{}
	}
}

func (doc *CVERaw) GetPublished() time.Time {
	published, err := clock.ParseRFC3339(doc.PublishedDate)
	if err == nil {
		published, _ = clock.InTimezone(published, clock.Local)
		return published
	} else {
		return time.Time{}
	}
}

func (doc *CVERaw) GetDescriptions() []string {
	descriptions := make([]string, 0)
	for _, description := range doc.Detail.Description.Data {
		descriptions = append(descriptions, description.Value)
	}
	// Success
	return descriptions
}

func (doc *CVERaw) GetReferences() []string {
	references := make([]string, 0)
	for _, reference := range doc.Detail.References.Data {
		if len(reference.Tags) > 0 {
			references = append(references, fmt.Sprintf("%v %s", reference.Tags, reference.Url))
		} else {
			references = append(references, reference.Url)
		}
	}
	// Success
	return references
}

func (doc *CVERaw) GetSeverityAndScore() (string, string, float32) {
	if doc.Impact.MetricV3.Vector.BaseSeverity != "" {
		return strings.ToLower(doc.Impact.MetricV3.Vector.BaseSeverity), doc.Impact.MetricV3.Vector.Version, doc.Impact.MetricV3.Vector.BaseScore
	} else if doc.Impact.MetricV2.Severity != "" {
		return strings.ToLower(doc.Impact.MetricV2.Severity), doc.Impact.MetricV2.Vector.Version, doc.Impact.MetricV2.Vector.BaseScore
	} else {
		return strings.ToLower(defs.TitleSeverityUnknown), "", 0
	}
}

func (doc *CVERaw) GetProducts() []string {
	results := make([]string, 0)
	for _, node := range doc.Configurations.Nodes {
		for _, product := range node.GetProducts() {
			if !slice.String(results).Contains(product) {
				results = append(results, product)
			}
		}
	}
	// Success
	return results
}

func (doc *CVENode) GetProducts() []string {
	results := make([]string, 0)
	for _, node := range doc.Match {
		results = append(results, node.Cpe23Uri)
	}
	// Recursive
	recursive := make([]string, 0)
	for _, child := range doc.Children {
		recur := child.GetProducts()
		if len(recur) != 0 {
			recursive = append(recursive, recur...)
		}
	}
	if len(recursive) == 0 {
		return results
	}
	// Success
	return append(results, recursive...)
}

func (doc *CVERaw) GetVendor(products []string) []string {
	vendors := make([]string, 0)
	for _, product := range products {
		cpe := strings.Split(product, ":")
		if len(cpe) >= 4 {
			vendor := strings.Title(cpe[3])
			if !slice.String(vendors).Contains(vendor) {
				vendors = append(vendors, vendor)
			}
		}
	}
	// Success
	return vendors
}

func (doc CVECheckListMetric) Calculate() int {
	point := 0
	if doc.Ability > 0 {
		point += doc.Ability
	}
	if doc.Affect > 0 {
		point += doc.Affect
	}
	if doc.Condition > 0 {
		point += doc.Condition
	}
	if doc.Exploit > 0 {
		point += doc.Exploit
	}
	if doc.Patch > 0 {
		point += doc.Patch
	}
	// Success
	return point
}

func (doc CVECheckListMetric) EQ(other CVECheckListMetric) bool {
	if doc.Ability == other.Ability &&
		doc.Affect == other.Affect &&
		doc.Condition == other.Condition &&
		doc.Exploit == other.Exploit &&
		doc.Patch == other.Patch {
		return true
	}
	return false
}

type ResponseNodata struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Detail  interface{} `json:"detail"`
}

func (body *RequestCVESearch) Verify() error {
	if body.Keyword != "" {
		body.Keyword = strings.ToLower(strings.TrimSpace(body.Keyword))
	}
	if body.CVEName != "" {
		body.Keyword = strings.ToUpper(strings.TrimSpace(body.Keyword))
	}
	if body.Checker != "" {
		body.Checker = strings.ToLower(body.Checker)
	}
	if len(body.InternalFlag) > 0 {
		for i, flag := range body.InternalFlag {
			body.InternalFlag[i] = strings.TrimSpace(flag)
		}
	}
	if len(body.Source) > 0 {
		validSources := map[string]bool{
			defs.SourceCveCraw: true,
			defs.SourceCve:     true,
		}
		for i, source := range body.Source {
			trimmed := strings.TrimSpace(source)
			if !validSources[trimmed] {
				return fmt.Errorf("invalid source value: %s. Only 'NVD' and 'Others' are allowed", trimmed)
			}
			body.Source[i] = trimmed
		}
	}
	if len(body.Customers) == 0 {
		body.Customers = make([]string, 0)
	}
	if body.Status == nil {
		body.Status = make([]int, 0)
	}
	if strings.TrimSpace(body.Severity.VTI.Version) == "" && len(body.Severity.VTI.Value) > 0 {
		body.Severity.VTI.Version = defs.VersionVcs10
	}
	if strings.TrimSpace(body.Severity.VTI.Version) != "" {
		if !slice.String(defs.EnumVTIVersion).Contains(strings.TrimSpace(body.Severity.VTI.Version)) {
			return errors.New("invalid value for param <severity.vti.version>")
		}
	}
	if body.Severity.VTI.Value == nil {
		body.Severity.VTI.Value = make([]int, 0)
	}

	if body.Severity.Global.Version == nil {
		body.Severity.Global.Version = make([]string, 0)
	}
	for _, it := range body.Severity.Global.Version {
		if strings.TrimSpace(it) != "" {
			if !slice.String(defs.EnumGlobalVersion).Contains(strings.TrimSpace(it)) {
				return errors.New("invalid value for param <severity.global.version>")
			}
		}
	}
	if body.Severity.Global.SeverityVersion2 == nil {
		body.Severity.Global.SeverityVersion2 = make([]int, 0)
	}
	if body.Severity.Global.SeverityVersion3 == nil {
		body.Severity.Global.SeverityVersion3 = make([]int, 0)
	}
	if len(body.Languages) > 0 {
		languages := make([]string, 0)
		for _, lang := range body.Languages {
			if !strings.Contains(lang, ",") {
				if _, ok := defs.MappingLanguage[lang]; !ok {
					return errors.New("invalid value for param <languages>")
				}
			}
			languages = append(languages, lang)
		}
		body.Languages = slice.String(languages).Unique().Extract()
	}
	if body.Time.Approved.Gte > 0 && body.Time.Approved.Lte > 0 && body.Time.Approved.Gte > body.Time.Approved.Lte {
		return errors.New("invalid value for param <time.approved.gte> greater than <time.approved.lte>")
	}
	if body.Time.Modified.Gte > 0 && body.Time.Modified.Lte > 0 && body.Time.Modified.Gte > body.Time.Modified.Lte {
		return errors.New("invalid value for param <time.modified.gte> greater than <time.modified.lte>")
	}
	if body.Time.AnalysisTime.Gte > 0 && body.Time.AnalysisTime.Lte > 0 && body.Time.AnalysisTime.Gte > body.Time.AnalysisTime.Lte {
		return errors.New("invalid value for param <time.modified.gte> greater than <time.modified.lte>")
	}
	body.Sort = make([]string, 0)
	if body.Time.Approved.Gte > 0 || body.Time.Approved.Lte > 0 {
		body.Sort = append(body.Sort, "-approved")
	}

	if body.Time.Modified.Gte > 0 || body.Time.Modified.Lte > 0 {
		body.Sort = append(body.Sort, "-modified")
	}

	if body.Time.AnalysisTime.Gte > 0 || body.Time.AnalysisTime.Lte > 0 {
		body.Sort = append(body.Sort, "-analysis_time")
	}

	if len(body.Sort) == 0 || len(body.Sort) > 1 {
		body.Sort = []string{"-analysis_time"}
	}
	if body.Size == 0 {
		body.Size = 20
	}

	if body.Time.Approved.Gte > 0 || body.Time.Approved.Lte > 0 {
		for _, it := range body.Status {
			if it == defs.StatusCodeApproved {
				body.Status = []int{2}
				break
			}
		}
		if len(body.Status) == 0 {
			body.Status = []int{2}
		}
	}
	return nil
}

func (body *RequestLifeCycleCVE) Verify() error {
	if len(body.CVECode) == 0 {
		body.CVECode = make([]string, 0)
	}
	return nil
}

func ProcessCVSSCNA(score float32, version, vectorString, source string) CVEMetric {
	if version == "" {
		return CVEMetric{}
	}
	cna := CVEMetric{
		Score:        score,
		Version:      version,
		VectorString: vectorString,
		Source:       source,
	}
	var rangeSeverityMap map[int]interface{}
	cna.Severity = defs.SeverityCodeUnknown
	switch {
	case strings.HasPrefix(version, "2."):
		rangeSeverityMap = defs.RangeCvssV2SeverityScore
	case strings.HasPrefix(version, "3."):
		rangeSeverityMap = defs.RangeCvssV3SeverityScore
	case strings.HasPrefix(version, "4."):
		rangeSeverityMap = defs.RangeCvssV4SeverityScore
	}
	if rangeSeverityMap != nil {
		for severity, point := range rangeSeverityMap {
			rPoint := point.(map[string]float32)
			if score >= rPoint["gte"] && score <= rPoint["lte"] {
				cna.Severity = severity
				break
			}
		}
	}
	return cna
}
