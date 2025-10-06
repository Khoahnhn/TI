package model

import (
	"fmt"

	"gitlab.viettelcyber.com/awesome-threat/library/hash"
)

type (
	AssetHistory struct {
		ID      string `json:"id"`
		Asset   string `json:"asset"`
		Action  string `json:"action"`
		Created int64  `json:"created"`
		Creator string `json:"creator"`
		Comment string `json:"comment"`
	}
)

func (doc *AssetHistory) GetID() string {
	// Success
	return doc.ID
}

func (doc *AssetHistory) GenID() {
	// Success
	doc.ID = hash.SHA1(fmt.Sprintf("%s--%d", doc.Asset, doc.Created))
}
