package elastic

import (
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic/db"
	"golang.org/x/net/context"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type assetHistoryRepository struct {
	con   db.Database
	index string
}

func NewAssetHistoryRepository(conf elastic.Config, index string) AssetHistoryRepository {
	if index == "" {
		index = defs.IndexAssetHistory
	}
	// Success
	return &assetHistoryRepository{con: elastic.NewService(conf), index: index}
}

func (inst *assetHistoryRepository) Name() string {
	// Success
	return inst.index
}

func (inst *assetHistoryRepository) Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.AssetHistory, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.AssetHistory, 0)
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

func (inst *assetHistoryRepository) FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.AssetHistory, error) {
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
	results := make([]*model.AssetHistory, 0)
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

func (inst *assetHistoryRepository) Count(ctx context.Context, query interface{}) (int64, error) {
	// Success
	return inst.con.Count(inst.Name(), "", query.(map[string]interface{}))
}

func (inst *assetHistoryRepository) Store(ctx context.Context, document *model.AssetHistory) error {
	if err := inst.con.InsertOne(inst.Name(), "", document); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *assetHistoryRepository) StoreAll(ctx context.Context, documents []*model.AssetHistory) error {
	if len(documents) == 0 {
		return nil
	}
	docs := make([]db.Document, 0)
	for _, doc := range documents {
		docs = append(docs, doc)
	}
	if err := inst.con.InsertMany(inst.Name(), "", docs); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *assetHistoryRepository) DeleteByID(ctx context.Context, id string) error {
	if err := inst.con.DeleteByID(inst.Name(), "", id); err != nil {
		return err
	}
	// Success
	return nil
}
