package elastic

import (
	"context"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type iocHistoryRepository struct {
	con elastic.Service
}

func NewIOCHistoryRepository(conf elastic.Config) IOCHistoryRepository {
	// Success
	return &iocHistoryRepository{con: elastic.NewService(conf)}
}

func (inst *iocHistoryRepository) Name() string {
	// Success
	return defs.IndexIOCHistory
}

func (inst *iocHistoryRepository) FindByIOCID(ctx context.Context, id string) ([]*model.IOCHistory, error) {
	query := map[string]interface{}{
		"term": map[string]interface{}{
			"ioc": id,
		},
	}
	// Success
	return inst.FindAll(ctx, inst.Name(), query, []string{"-created"})
}

func (inst *iocHistoryRepository) Find(ctx context.Context, index string, query interface{}, sorts []string, offset, size int) ([]*model.IOCHistory, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.IOCHistory, 0)
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

func (inst *iocHistoryRepository) FindAll(ctx context.Context, index string, query interface{}, sorts []string) ([]*model.IOCHistory, error) {
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
	results := make([]*model.IOCHistory, 0)
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

func (inst *iocHistoryRepository) Store(ctx context.Context, document *model.IOCHistory) error {
	if err := inst.con.InsertOne(inst.Name(), "", document); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *iocHistoryRepository) StoreAll(ctx context.Context, documents []*model.IOCHistory) error {
	if len(documents) == 0 {
		return nil
	}
	docs := make([]elastic.Document, 0)
	for _, document := range documents {
		docs = append(docs, document)
	}
	if err := inst.con.InsertMany(inst.Name(), "", docs); err != nil {
		return err
	}
	// Success
	return nil
}
