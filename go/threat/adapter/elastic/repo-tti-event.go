package elastic

import (
	"context"
	"fmt"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type ttiEventRepository struct {
	con elastic.Service
}

func NewTTIEventRepository(conf elastic.Config) TTIEventRepository {
	// Success
	return &ttiEventRepository{con: elastic.NewService(conf)}
}

func (inst *ttiEventRepository) Name() string {
	// Success
	return defs.IndexTTIEvent
}

func (inst *ttiEventRepository) GetByID(ctx context.Context, org, id string) (*model.TTIEvent, error) {
	var result model.TTIEvent
	if err := inst.con.Get(fmt.Sprintf(inst.Name(), org), "", id, &result); err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (inst *ttiEventRepository) Find(ctx context.Context, org string, query interface{}, sorts []string, offset, size int) ([]*model.TTIEvent, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.TTIEvent, 0)
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

func (inst *ttiEventRepository) FindAll(ctx context.Context, org string, query interface{}, sorts []string) ([]*model.TTIEvent, error) {
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
	results := make([]*model.TTIEvent, 0)
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
