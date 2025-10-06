package model

import (
	"fmt"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"regexp"
)

type (
	CVEInternalFlag struct {
		ID       string `json:"id"`
		FlagName string `json:"flag_name"`
		Date     int64  `json:"date"`
	}

	RequestInternalFlagSearch struct {
		Keyword string `json:"keyword"`
		Size    int    `json:"size" validate:"numeric,gte=0"`
		Offset  int    `json:"offset" validate:"numeric,gte=0"`
	}

	InternalFlagResponse struct {
		Data  []*CVEInternalFlag `json:"data"`
		Total int64              `json:"total"`
	}
)

func (doc *CVEInternalFlag) GetID() string {
	return doc.ID
}

func (doc *CVEInternalFlag) SetEID(id string) {
	doc.ID = id
}

func (doc *CVEInternalFlag) GenID() {
	doc.ID = hash.SHA1(fmt.Sprintf("%s", doc.FlagName))
}

func (bodyRequestInternalFlagSearch *RequestInternalFlagSearch) PrepareQuery() map[string]interface{} {
	if bodyRequestInternalFlagSearch.Keyword == "" {
		return map[string]interface{}{"match_all": map[string]interface{}{}}
	}
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"should": []interface{}{
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"flag_name.raw": map[string]interface{}{
							"value": fmt.Sprintf("*%s*", regexp.QuoteMeta(bodyRequestInternalFlagSearch.Keyword)),
							"boost": 2,
						},
					},
				},
				map[string]interface{}{
					"match": map[string]interface{}{
						"flag_name": map[string]interface{}{
							"query":     bodyRequestInternalFlagSearch.Keyword,
							"fuzziness": "AUTO",
							"boost":     1,
						},
					},
				},
			},
			"minimum_should_match": 1,
		},
	}
}
