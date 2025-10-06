package elastic

import (
	"context"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type cpeRepository struct {
	con elastic.Service
}

func NewCPERepository(conf elastic.Config) CPERepository {
	// Success
	return &cpeRepository{con: elastic.NewService(conf)}
}

func (inst *cpeRepository) Name() string {
	// Success
	return defs.IndexCpe
}

func (inst *cpeRepository) GetByID(ctx context.Context, id string) (*model.CPE, error) {
	var result model.CPE
	if err := inst.con.Get(inst.Name(), "", id, &result); err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (inst *cpeRepository) Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.CPE, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.CPE, 0)
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

func (inst *cpeRepository) FindByValue(ctx context.Context, value string) (*model.CPE, error) {
	id := hash.SHA1(value)
	// Success
	return inst.GetByID(ctx, id)
}

func (inst *cpeRepository) FindCollapse(ctx context.Context, query interface{}, sorts []string, field string, offset, size int) ([]*model.CPE, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.CPE, 0)
	_, err := inst.con.FindCollapse(
		inst.Name(),
		"",
		query.(map[string]interface{}),
		sorts,
		field,
		offset,
		size,
		&results)
	if err != nil {
		return nil, err
	}
	// Success
	return results, nil
}

func (inst *cpeRepository) FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.CPE, error) {
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
	results := make([]*model.CPE, 0)
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

func (inst *cpeRepository) Count(ctx context.Context, query interface{}) (int64, error) {
	// Success
	return inst.con.Count(inst.Name(), "", query.(map[string]interface{}))
}

func (inst *cpeRepository) Store(ctx context.Context, document *model.CPE) error {
	if err := inst.con.InsertOne(inst.Name(), "", document); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *cpeRepository) DeleteByID(ctx context.Context, id string) error {
	if err := inst.con.DeleteByID(inst.Name(), "", id); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *cpeRepository) AggregationCount(ctx context.Context, query interface{}, fields []string) (map[string][]elastic.ResultAggregationCount, error) {
	// Success
	return inst.con.AggregationCount(inst.Name(), "", query.(map[string]interface{}), fields)
}
