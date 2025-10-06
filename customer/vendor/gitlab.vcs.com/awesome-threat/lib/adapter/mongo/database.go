package mongo

type (
	// Document
	Document interface {
		GetID() interface{}
	}

	ResultAggregationCount struct {
		Value interface{} `json:"value"`
		Count int64       `json:"count"`
	}
)
