package elastic

import (
	"context"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic/db"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type assetRepository struct {
	con   db.Database
	index string
}

func NewAssetRepository(conf elastic.Config, index string) AssetRepository {
	if index == "" {
		index = defs.IndexAsset
	}
	// Success
	return &assetRepository{con: elastic.NewService(conf), index: index}
}

func (inst *assetRepository) Name() string {
	// Success
	return inst.index
}

func (inst *assetRepository) GetByID(ctx context.Context, id string) (*model.Asset, error) {
	var result model.Asset
	if err := inst.con.Get(inst.Name(), "", id, &result); err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (inst *assetRepository) Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.Asset, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.Asset, 0)
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

func (inst *assetRepository) FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.Asset, error) {
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
	results := make([]*model.Asset, 0)
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

func (inst *assetRepository) Count(ctx context.Context, query interface{}) (int64, error) {
	// Success
	return inst.con.Count(inst.Name(), "", query.(map[string]interface{}))
}

func (inst *assetRepository) Store(ctx context.Context, document *model.Asset) error {
	if err := inst.con.InsertOne(inst.Name(), "", document); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *assetRepository) StoreAll(ctx context.Context, documents []*model.Asset) error {
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

func (inst *assetRepository) Update(ctx context.Context, document *model.Asset) error {
	if err := inst.con.UpdateByID(inst.Name(), "", document.GetID(), document, true); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *assetRepository) DeleteByID(ctx context.Context, id string) error {
	if err := inst.con.DeleteByID(inst.Name(), "", id); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *assetRepository) AggregationCount(ctx context.Context, query interface{}, fields []string) (map[string][]db.ResultAggregationCount, error) {
	// Success
	return inst.con.AggregationCount(inst.Name(), "", query.(map[string]interface{}), fields)
}
