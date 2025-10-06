package elastic

import (
	"context"

	"ws-lookup/defs"
	"ws-lookup/model"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
)

type cveRepository struct {
	con elastic.Service
}

func NewCVERepository(conf elastic.Config) CVERepository {
	// Success
	return &cveRepository{con: elastic.NewService(conf)}
}

func (inst *cveRepository) Find(ctx context.Context, index string, query interface{}, sorts []string, offset, size int) ([]*model.CVE, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.CVE, 0)
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

func (inst *cveRepository) FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.CVE, error) {
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
	results := make([]*model.CVE, 0)
	results, err := inst.Find(ctx, inst.Name(), query, sorts, offset, size)
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

func (inst *cveRepository) Name() string {
	// Success
	return defs.IndexCVE
}

func (inst *cveRepository) FindByValues(values []string) ([]*model.CVE, error) {
	query := map[string]interface{}{
		"terms": map[string]interface{}{
			"name": values,
		},
	}
	// Success
	return inst.FindAll(context.Background(), query, []string{"+name"})
}
