package elastic

import (
	"context"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type cpePopularRepository struct {
	con elastic.Service
}

func NewCPEPopularRepository(conf elastic.Config) CPEPopularRepository {
	// Success
	return &cpePopularRepository{con: elastic.NewService(conf)}
}

func (inst *cpePopularRepository) Name() string {
	// Success
	return defs.IndexCpePopular
}

func (inst *cpePopularRepository) GetByID(ctx context.Context, id string) (*model.CPEPopular, error) {
	var result model.CPEPopular
	if err := inst.con.Get(inst.Name(), "", id, &result); err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (inst *cpePopularRepository) Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.CPEPopular, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.CPEPopular, 0)
	_, err := inst.con.FindOffset(
		inst.Name(),
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

func (inst *cpePopularRepository) FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.CPEPopular, error) {
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
	results := make([]*model.CPEPopular, 0)
	results, err := inst.Find(ctx, query, sorts, offset, size)
	if err != nil || len(results) == 0 {
		return results, err
	}
	// Recursive
	ctx = context.WithValue(ctx, "size", size)
	ctx = context.WithValue(ctx, "offset", offset+size)
	recursiveResults, err := inst.FindAll(ctx, query, sorts)
	if err != nil || len(recursiveResults) == 0 {
		return results, nil
	}
	// Success
	return append(results, recursiveResults...), nil
}

func (inst *cpePopularRepository) Count(ctx context.Context, query interface{}) (int64, error) {
	// Success
	return inst.con.Count(inst.Name(), "", query.(map[string]interface{}))
}

func (inst *cpePopularRepository) Store(ctx context.Context, document *model.CPEPopular) error {
	if err := inst.con.InsertOne(inst.Name(), "", document); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *cpePopularRepository) DeleteByID(ctx context.Context, id string) error {
	if err := inst.con.DeleteByID(inst.Name(), "", id); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *cpePopularRepository) AggregationCount(ctx context.Context, query interface{}, fields []string) (map[string][]elastic.ResultAggregationCount, error) {
	// Success
	return inst.con.AggregationCount(inst.Name(), "", query.(map[string]interface{}), fields)
}
