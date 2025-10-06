package model

import (
	"time"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
)

type (
	// Document
	IntelligenceExport struct {
		From    string                    `json:"from"`
		To      string                    `json:"to"`
		Summary IntelligenceSummaryExport `json:"summary"`
		Detail  IntelligenceDetailExport  `json:"detail"`
	}
	BrandAbuseExport struct {
		From    string             `json:"from"`
		To      string             `json:"to"`
		Summary BrandSummaryExport `json:"summary"`
		Detail  BrandDetailExport  `json:"detail"`
	}

	BrandSummaryExport struct {
		Target  string         `json:"target"`
		Package string         `json:"package"`
		Detail  map[string]int `json:"detail"`
	}

	BrandDetailExport struct {
		Domain   string `json:"domain"`
		Created  string `json:"created"`
		Target   string `json:"target"`
		Category string `json:"category"`
	}

	IntelligenceSummaryExport struct {
		TotalCritical int `json:"total_critical"`
		TotalHigh     int `json:"total_high"`
		TotalMedium   int `json:"total_medium"`
		TotalLow      int `json:"total_low"`
		TotalSLAPass  int `json:"total_sla_pass"`
		TotalSLAFail  int `json:"total_sla_fail"`
		TotalSLANa    int `json:"total_sla_na"`
	}

	IntelligenceDetailExport struct {
		Title    string `json:"title"`
		Created  string `json:"created"`
		Summary  string `json:"summary"`
		Severity string `json:"severity"`
		Appeared string `json:"appeared"`
		Status   string `json:"status"`
		Policy   string `json:"policy"`
	}

	TTIAlertExport struct {
		Summary TTIAlertSummaryExport `json:"summary"`
		Detail  TTIAlertDetailExport  `json:"detail"`
	}

	TTIAlertSummaryExport struct {
		TotalCritical int `json:"total_critical"`
		TotalHigh     int `json:"total_high"`
		TotalMedium   int `json:"total_medium"`
		TotalLow      int `json:"total_low"`
	}

	TTIAlertDetailExport struct {
		Timestamp time.Time
		Created   string `json:"created"`
		Category  string `json:"category"`
		Title     string `json:"title"`
		Object    string `json:"object"`
		Severity  string `json:"severity"`
		Message   string `json:"message"`
		Link      string `json:"link"`
	}

	TTIAlertDetailExports []*TTIAlertDetailExport

	TTISupportExport struct {
		Summary TTISupportSummaryExport `json:"summary"`
		Detail  TTISupportDetailExport  `json:"detail"`
	}

	TTISupportSummaryExport struct {
		TotalPending    int `json:"total_pending"`
		TotalInprogress int `json:"total_inprogress"`
		TotalDone       int `json:"total_done"`
		TotalReject     int `json:"reject"`
	}

	TTISupportDetailExport struct {
		Created  string `json:"created"`
		Updated  string `json:"updated"`
		Process  string `json:"process"`
		Object   string `json:"object"`
		Category string `json:"category"`
		Status   string `json:"status"`
	}
)

func (body *IntelligenceSummaryExport) Calculate(detail IntelligenceDetailExport) {
	// Severity
	switch detail.Severity {
	case defs.TitleCritical, defs.TitleCriticalEN:
		body.TotalCritical += 1
	case defs.TitleHigh, defs.TitleHighEN:
		body.TotalHigh += 1
	case defs.TitleMedium, defs.TitleMediumEN:
		body.TotalMedium += 1
	case defs.TitleLow, defs.TitleLowEN:
		body.TotalLow += 1
	}
	// Status
	switch detail.Status {
	case defs.SLAPass:
		body.TotalSLAPass += 1
	case defs.SLAFail:
		body.TotalSLAFail += 1
	case defs.SLANa:
		body.TotalSLANa += 1
	}
}

func (doc *TTIAlertSummaryExport) Calculate(detail TTIAlertDetailExport) {
	// Severity
	switch detail.Severity {
	case defs.TitleCritical, defs.TitleCriticalEN:
		doc.TotalCritical += 1
	case defs.TitleHigh, defs.TitleHighEN:
		doc.TotalHigh += 1
	case defs.TitleMedium, defs.TitleMediumEN:
		doc.TotalMedium += 1
	case defs.TitleLow, defs.TitleLowEN:
		doc.TotalLow += 1
	}
}

func (doc *TTISupportSummaryExport) Calculate(detail TTISupportDetailExport) {
	// Status
	switch detail.Status {
	case defs.TitlePending, defs.TitlePendingEN:
		doc.TotalPending += 1
	case defs.TitleInprogress, defs.TitleInprogressEN:
		doc.TotalInprogress += 1
	case defs.TitleDone, defs.TitleDoneEN:
		doc.TotalDone += 1
	case defs.TitleReject, defs.TitleRejectEN:
		doc.TotalReject += 1
	}
}

func (doc TTIAlertDetailExports) Len() int {
	// Success
	return len(doc)
}

func (doc TTIAlertDetailExports) Less(i, j int) bool {
	// Success
	return doc[i].Timestamp.Before(doc[j].Timestamp)
}

func (doc TTIAlertDetailExports) Swap(i, j int) {
	// Success
	doc[i], doc[j] = doc[j], doc[i]
}

type ExportData struct {
	ID                string `json:"id"`
	PublishedTime     string `json:"published_time"`
	CreateTime        string `json:"create_time"`
	AnalysisTime      string `json:"analysis_time"`
	ApprovedTime      string `json:"approved_time"`
	AlertTime         string `json:"alert_time"`
	CVEName           string `json:"cve_name"`
	Owner             string `json:"owner"`
	Product           string `json:"product"`
	Description       string `json:"description"`
	SeverityCVSS      string `json:"severity_cvss"`
	SeSeverityCVSSNum defs.Severity
	CVSSVersion       string `json:"cvss_version"`
	SeverityVCS       string `json:"severity_vcs"`
	SeSeverityVCSNum  defs.Severity
	UserChecklist     string `json:"user_checklist"`
	Status            string `json:"status"`
	ProcessDeltaTime  string `json:"process_delta_time"`
	ProcessSLA        string `json:"process_sla"`
	ServiceDeltaTime  string `json:"service_delta_time"`
	ServiceSLA        string `json:"service_sla"`
	Language          string `json:"language"`
	Customer          int    `json:"customer"`
	Source            string `json:"source"`
}
