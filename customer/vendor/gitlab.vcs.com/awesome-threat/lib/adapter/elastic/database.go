package elastic

type (
	// Map
	M map[string]interface{}
	// Query
	Doc   M
	Query M
	// Document
	Document interface {
		GetID() string
		SetEID(id string)
	}

	UpdateDocument struct {
		ID     string      `json:"id"`
		Update interface{} `json:"update"`
	}

	ResultAggregationCount struct {
		Value interface{} `json:"value"`
		Count int64       `json:"count"`
	}
)

func (doc Doc) GetID() string {
	if value, ok := doc["id"]; ok {
		return value.(string)
	}
	return ""
}

func (q Query) Source() (interface{}, error) {
	return q, nil
}
