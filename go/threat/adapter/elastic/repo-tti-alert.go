package elastic

import (
	"context"
	"fmt"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type ttiAlertRepository struct {
	con elastic.Service
}

func NewTTIAlertRepository(conf elastic.Config) TTIAlertRepository {
	// Success
	return &ttiAlertRepository{con: elastic.NewService(conf)}
}

func (inst *ttiAlertRepository) Name() string {
	// Success
	return defs.IndexTTIAlert
}

func (inst *ttiAlertRepository) Find(ctx context.Context, org string, query interface{}, sorts []string, offset, size int) ([]*model.TTIAlert, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.TTIAlert, 0)
	_, err := inst.con.FindOffset(
		fmt.Sprintf(inst.Name(), org),
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

func (inst *ttiAlertRepository) FindAll(ctx context.Context, org string, query interface{}, sorts []string) ([]*model.TTIAlert, error) {
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
	results := make([]*model.TTIAlert, 0)
	results, err := inst.Find(ctx, org, query, sorts, offset, size)
	if err != nil || len(results) == 0 {
		return results, err
	}
	// Recursive
	ctx = context.WithValue(ctx, "size", size)
	ctx = context.WithValue(ctx, "offset", offset+size)
	recursiveResults, err := inst.FindAll(ctx, org, query, sorts)
	if err != nil || len(recursiveResults) == 0 {
		return results, nil
	}
	// Success
	return append(results, recursiveResults...), nil
}
