package elastic

import (
	"context"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type cveRepository struct {
	con elastic.Service
}

func NewCVERepository(conf elastic.Config) CVERepository {
	// Success
	return &cveRepository{con: elastic.NewService(conf)}
}

func (inst *cveRepository) Name() string {
	// Success
	return defs.IndexCve
}

func (inst *cveRepository) GetByID(ctx context.Context, id string) (*model.CVE, error) {
	var result model.CVE
	if err := inst.con.Get(inst.Name(), "", id, &result); err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (inst *cveRepository) Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.CVE, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.CVE, 0)
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

func (inst *cveRepository) Count(ctx context.Context, query interface{}) (int64, error) {
	// Success
	return inst.con.Count(inst.Name(), "", query.(map[string]interface{}))
}

func (inst *cveRepository) Store(ctx context.Context, document *model.CVE) error {
	if err := inst.con.InsertOne(inst.Name(), "", document); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *cveRepository) AggregationCount(ctx context.Context, query interface{}, fields []string) (map[string][]elastic.ResultAggregationCount, error) {
	// Success
	return inst.con.AggregationCount(inst.Name(), "", query.(map[string]interface{}), fields)
}

func (inst *cveRepository) AggregationCountWithSize(ctx context.Context, query interface{}, fields map[string]int) (map[string][]elastic.ResultAggregationCount, error) {
	// Success
	return inst.con.AggregationCountWithSize(inst.Name(), "", query.(map[string]interface{}), fields)
}
