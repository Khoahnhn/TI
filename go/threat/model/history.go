package model

import (
	"fmt"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
)

type (
	History struct {
		ID          string `json:"id"`
		Created     int64  `json:"created"`
		Document    string `json:"document"`
		Editor      string `json:"editor"`
		Action      string `json:"action"`
		Description string `json:"description"`
		HistoryType string `json:"history_type"`
	}

	HistoryListItem struct {
		ID          string `json:"id"`
		Created     int64  `json:"created"`
		Document    string `json:"document"`
		Editor      string `json:"editor"`
		Action      string `json:"action"`
		Description string `json:"description"`
		HistoryType string `json:"history_type"`
	}

	RequestHistorySearch struct {
		ID       string `json:"id" param:"id"`
		FromDate int64  `json:"from_data" query:"from_data"`
		ToDate   int64  `json:"to_data" query:"to_data"`
		Size     int    `query:"size"  validate:"numeric,gte=0"`
		Offset   int    `query:"offset" validate:"numeric,gte=0"`
	}

	HistoryResponse struct {
		Data  []*HistoryListItem `json:"data"`
		Total int64              `json:"total"`
	}
)

func (doc *History) GetID() string {
	// Success
	return doc.ID
}

func (doc *History) SetEID(id string) {
	// Success
	doc.ID = id
}

func (doc *History) GenID() {
	// Success
	doc.ID = hash.SHA1(fmt.Sprintf("%s--%d--%s", doc.Document, doc.Created, doc.Editor))
}

func (body *RequestHistorySearch) PrepareQuery() map[string]interface{} {
	filter := []interface{}{
		map[string]interface{}{
			"term": map[string]interface{}{
				"document": body.ID,
			},
		},
	}
	return map[string]interface{}{
		"bool": map[string][]interface{}{
			"filter": filter,
		},
	}
}
