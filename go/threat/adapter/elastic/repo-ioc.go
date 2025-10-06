package elastic

import (
	"context"
	"errors"
	"fmt"

	es "github.com/olivere/elastic/v7"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/arrayx"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type iocRepository struct {
	con elastic.Service
}

func NewIOCRepository(conf elastic.Config) IOCRepository {
	// Success
	return &iocRepository{con: elastic.NewService(conf)}
}

func (inst *iocRepository) Name() string {
	// Success
	return defs.IndexIOC
}

func (inst *iocRepository) FindByID(ctx context.Context, id string) (*model.IOC, error) {
	query := map[string]interface{}{
		"term": map[string]interface{}{
			"id": id,
		},
	}
	documents, err := inst.Find(ctx, fmt.Sprintf(inst.Name(), "*"), query, []string{}, 0, 1)
	if err != nil {
		return nil, err
	}
	if len(documents) == 0 {
		return nil, errors.New(elastic.NotFoundError)
	}
	// Success
	return documents[0], nil
}

func (inst *iocRepository) Find(ctx context.Context, index string, query interface{}, sorts []string, offset, size int) ([]*model.IOC, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.IOC, 0)
	_, err := inst.con.FindOffset(
		index,
		"",
		query.(map[string]interface{}),
		sorts,
		offset,
		size,
		&results)
	if err != nil {
		return nil, err
	}
	// Success
	return results, nil
}

func (inst *iocRepository) FindAll(ctx context.Context, index string, query interface{}, sorts []string) ([]*model.IOC, error) {
	size := 0
	offset := 0
	if value := ctx.Value("size"); value != nil {
		size = value.(int)
	}
	if size == 0 {
		size = 100
	}
	if value := ctx.Value("offset"); value != nil {
		offset = value.(int)
	}
	results := make([]*model.IOC, 0)
	results, err := inst.Find(ctx, index, query, sorts, offset, size)
	if err != nil || len(results) == 0 {
		return results, err
	}
	// Recursive
	ctx = context.WithValue(ctx, "size", size)
	ctx = context.WithValue(ctx, "offset", offset+size)
	recursiveResults, err := inst.FindAll(ctx, index, query, sorts)
	if err != nil || len(recursiveResults) == 0 {
		return results, nil
	}
	// Success
	return append(results, recursiveResults...), nil
}

func (inst *iocRepository) Count(ctx context.Context, index string, query interface{}) (int64, error) {
	// Success
	return inst.con.Count(index, "", query.(map[string]interface{}))
}

func (inst *iocRepository) GetByID(ctx context.Context, index, id string) (*model.IOC, error) {
	var result model.IOC
	if err := inst.con.Get(index, "", id, &result); err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (inst *iocRepository) StoreAll(ctx context.Context, documents []*model.IOC) error {
	docs := map[string][]elastic.Document{}
	for _, document := range documents {
		index, ok := defs.MappingIOCIndex[document.Type]
		if ok {
			if value, ok := docs[index]; ok {
				value = append(value, document)
				docs[index] = value
			} else {
				docs[index] = []elastic.Document{document}
			}
		}
	}
	for index, items := range docs {
		if len(items) > 0 {
			if err := inst.con.InsertMany(index, "", items); err != nil {
				return err
			}
		}
	}
	// Success
	return nil
}

func (inst *iocRepository) Update(ctx context.Context, index string, document *model.IOC) error {
	if err := inst.con.UpdateByID(index, "", document.GetID(), document, false); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *iocRepository) AggregationCount(ctx context.Context, index string, query interface{}, fields []string) (map[string][]elastic.ResultAggregationCount, error) {
	// Success
	return inst.con.AggregationCount(index, "", query.(map[string]interface{}), fields)
}

func (inst *iocRepository) AggregationTopHits(ctx context.Context, index string, query interface{}, field string, size int) ([]string, error) {
	aggTopHits := es.NewTopHitsAggregation().Size(1)
	aggs := es.NewTermsAggregation().Size(size).Field(field).SubAggregation("top_hits", aggTopHits)
	res, err := inst.con.Aggregation(index, "", query.(map[string]interface{}), map[string]es.Aggregation{"terms": aggs})
	if err != nil {
		return nil, err
	}
	resTermsAgg, ok := res.Terms("terms")
	if !ok {
		return make([]string, 0), nil
	}
	result := make([]string, 0)
	for _, bucket := range resTermsAgg.Buckets {
		result = append(result, bucket.Key.(string))
	}
	result = arrayx.Unique(result)
	// Success
	return result, nil
}
