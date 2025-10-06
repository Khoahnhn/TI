package elastic

import (
	es "github.com/olivere/elastic/v7"
)

type Service interface {
	Get(database, collection, id string, result Document) error
	Exists(database, collection, id string) (bool, error)
	Count(database, collection string, query Query) (int64, error)
	FindOne(database, collection string, query Query, sorts []string, result interface{}) error
	FindPaging(database, collection string, query Query, sorts []string, page, size int, results interface{}) (int64, error)
	FindOffset(database, collection string, query Query, sorts []string, offset, size int, results interface{}) (int64, error)
	FindScroll(database, collection string, query Query, sorts []string, size int, scrollID, keepAlive string, result interface{}) (string, int64, error)
	FindCollapse(database, collection string, query Query, sorts []string, field string, offset, size int, results interface{}) (int64, error)
	InsertOne(database, collection string, doc Document) error
	InsertMany(database, collection string, docs []Document) error
	UpdateByID(database, collection, id string, update interface{}, upsert bool) error
	UpdateMany(database, collection string, updates []UpdateDocument) error
	DeleteByID(database, collection, id string) error
	DeleteMany(database, collection string, query Query) error
	Aggregation(database, _ string, query Query, aggregations map[string]es.Aggregation) (*es.Aggregations, error)
	AggregationCount(database, collection string, query Query, fields []string) (map[string][]ResultAggregationCount, error)
	AggregationCountWithSize(database, collection string, query Query, fields map[string]int) (map[string][]ResultAggregationCount, error)
}
