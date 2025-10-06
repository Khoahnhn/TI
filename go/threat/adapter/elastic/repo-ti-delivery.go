package elastic

import (
	"context"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type tiDeliveryRepository struct {
	con elastic.Service
}

func NewTIDeliveryRepository(conf elastic.Config) TIDeliveryRepository {
	// Success
	return &tiDeliveryRepository{con: elastic.NewService(conf)}
}

func (inst *tiDeliveryRepository) Name() string {
	// Success
	return defs.IndexTIDelivery
}

func (inst *tiDeliveryRepository) GetByID(ctx context.Context, id string) (*model.Delivery, error) {
	var result model.Delivery
	if err := inst.con.Get(inst.Name(), "", id, &result); err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (inst *tiDeliveryRepository) Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.Delivery, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.Delivery, 0)
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

func (inst *tiDeliveryRepository) FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.Delivery, error) {
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
	results := make([]*model.Delivery, 0)
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
