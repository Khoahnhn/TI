package model

import "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"

type (
	RangeInt64 struct {
		Gte int64 `json:"gte"`
		Lte int64 `json:"lte"`
	}

	Float64Aggregations []elastic.ResultAggregationCount

	Language struct {
		VI interface{} `json:"vi"`
		EN interface{} `json:"en"`
	}
)

func (doc Float64Aggregations) Len() int {
	// Success
	return len(doc)
}

func (doc Float64Aggregations) Less(i, j int) bool {
	// Success
	return doc[i].Value.(float64) < doc[j].Value.(float64)
}

func (doc Float64Aggregations) Swap(i, j int) {
	// Success
	doc[i], doc[j] = doc[j], doc[i]
}
