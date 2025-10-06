package model

import "gitlab.viettelcyber.com/awesome-threat/library/clock"

type (
	RangeInt64 struct {
		Gte int64 `json:"gte" query:"gte"`
		Lte int64 `json:"lte" query:"lte"`
	}

	IndexResult struct {
		Hits struct {
			Total struct {
				Value float64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
	}

	AggregationResult struct {
		Aggregation map[string]AggregationBucket `json:"aggregations"`
	}

	AggregationBucket struct {
		Buckets []AggregationBucketElem `json:"buckets"`
	}

	AggregationBucketElem struct {
		Key   string `json:"key"`
		Count int    `json:"doc_count"`
	}
)

func (body *RangeInt64) Query(field string) (map[string]interface{}, bool) {
	timeFilter := map[string]interface{}{}
	if body.Gte > 0 {
		gte, _ := clock.ParseMilliTimestamp(body.Gte, clock.Local)
		timeFilter["gte"] = clock.UnixMilli(gte)
	}
	if body.Lte > 0 {
		lte, _ := clock.ParseMilliTimestamp(body.Lte, clock.Local)
		timeFilter["lte"] = clock.UnixMilli(lte)
	}
	if len(timeFilter) == 0 {
		return nil, false
	}
	// Success
	return map[string]interface{}{"range": map[string]interface{}{field: timeFilter}}, true
}
