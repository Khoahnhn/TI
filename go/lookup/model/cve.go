package model

import (
	"gitlab.viettelcyber.com/awesome-threat/library/core/cpe"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
)

type (
	CVE struct {
		EID          string   `json:"-"`
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Created      int64    `json:"created"`
		Modified     int64    `json:"modified"`
		Latest       int64    `json:"latest"`
		Published    int64    `json:"published"`
		Crawled      int64    `json:"crawled"`
		Vendor       []string `json:"vendor"`
		Affect       int64    `json:"affect"`
		Customer     []string `json:"customer"`
		Match        []string `json:"match"`
		Status       int      `json:"status"`
		Score        CVEScore `json:"score"`
		Checker      string   `json:"checker"`
		Languages    []string `json:"languages"`
		Approved     int64    `json:"approved"`
		AnalysisTime int64    `json:"analysis_time"`
	}

	CVEScore struct {
		Global CVEMetric `json:"global"`
		VTI    CVEMetric `json:"vti"`
	}

	CVEMetric struct {
		Score    float32 `json:"score"`
		Version  string  `json:"version"`
		Severity int     `json:"severity"`
	}
)

func (doc *CVE) GetID() string {
	// Success
	return doc.ID
}

func (doc *CVE) SetEID(id string) {
	// Success
	doc.EID = id
	doc.ID = doc.EID
}

func (doc *CVE) GetProducts() []string {
	results := make([]string, 0)
	for _, product := range doc.Match {
		pro, err := cpe.NewItemFromFormattedString(product)
		if err == nil {
			results = append(results, pro.Product().String())
		}
	}
	results = slice.String(results).Unique().Extract()
	// Success
	return results
}
