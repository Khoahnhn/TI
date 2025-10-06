package model

import (
	"encoding/json"
	"fmt"

	"gitlab.viettelcyber.com/awesome-threat/library/hash"
)

type (
	Asset struct {
		ID           string      `json:"id"`
		Title        string      `json:"title"`
		Value        string      `json:"value"`
		Created      int64       `json:"created"`
		Modified     int64       `json:"modified"`
		ApprovedAt   int64       `json:"approved_at"` // Thoi diem phe duyet hoac tu choi
		Type         string      `json:"type"`
		Visible      bool        `json:"visible"`
		Active       bool        `json:"active"`
		Status       int         `json:"status"`
		Creator      string      `json:"creator"`
		Organization string      `json:"organization"`
		Attribute    interface{} `json:"attribute"`
		Tags         []string    `json:"tags"`
		Reason       string      `json:"reason"` // Ly do tu choi
		SLA          int64       `json:"sla"`
	}

	AssetSummary struct {
		Value string `json:"value"`
		Type  string `json:"type"`
	}

	RequestAssetAction struct {
		IDs    []string `json:"ids" validate:"required"`
		Action string   `json:"action" validate:"required"`
		Reason string   `json:"reason"`
	}

	RequestAssetHistory struct {
		ID     string `json:"id" param:"id" validate:"required"`
		Offset int    `json:"offset" validate:"numeric,gte=0"`
		Size   int    `json:"size" validate:"numeric,gte=0"`
	}
)

func (doc *Asset) GetID() string {
	// Success
	return doc.ID
}

func (doc *Asset) GenID() {
	// Success
	doc.ID = hash.SHA1(fmt.Sprintf("%s--%s--%s", doc.Organization, doc.Type, doc.Value))
}

func (doc *Asset) GetProductAttribute() (*ProductAttribute, error) {
	bts, err := json.Marshal(doc.Attribute)
	if err != nil {
		return nil, err
	}
	var result ProductAttribute
	if err = json.Unmarshal(bts, &result); err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (doc *Asset) Clone() *Asset {
	return &Asset{
		ID:           doc.ID,
		Title:        doc.Title,
		Value:        doc.Title,
		Created:      doc.Created,
		Modified:     doc.Modified,
		ApprovedAt:   doc.ApprovedAt,
		Type:         doc.Type,
		Visible:      doc.Visible,
		Active:       doc.Active,
		Status:       doc.Status,
		Creator:      doc.Creator,
		Organization: doc.Organization,
		Attribute:    doc.Attribute,
		Tags:         doc.Tags,
		Reason:       doc.Reason,
		SLA:          doc.SLA,
	}
}

func (body RequestAssetHistory) Query() map[string]interface{} {
	// Success
	return map[string]interface{}{
		"term": map[string]interface{}{
			"asset": body.ID,
		},
	}
}
