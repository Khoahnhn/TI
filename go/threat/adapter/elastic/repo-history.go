package elastic

import (
	"context"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type historyRepository struct {
	con elastic.Service
}

func NewHistoryRepository(conf elastic.Config) HistoryRepository {
	// Success
	return &historyRepository{con: elastic.NewService(conf)}
}

func (inst *historyRepository) Name() string {
	// Success
	return defs.IndexCveHistory
}

func (inst *historyRepository) Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.History, int64, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*model.History, 0)
	total, err := inst.con.FindOffset(
		inst.Name(),
		"",
		query.(map[string]interface{}),
		sorts,
		offset,
		size,
		&results)
	if err != nil {
		return nil, 0, err
	}
	// Success
	return results, total, nil
}

func (inst *historyRepository) FindByDocument(ctx context.Context, id string, sorts []string, offset, size int) ([]*model.History, int64, error) {
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"document": id,
					},
				},
			},
		},
	}
	// Success
	return inst.Find(ctx, query, sorts, offset, size)
}

func (inst *historyRepository) Count(ctx context.Context, query interface{}) (int64, error) {
	// Success
	return inst.con.Count(inst.Name(), "", query.(map[string]interface{}))
}

func (inst *historyRepository) Store(ctx context.Context, document *model.History) error {
	if err := inst.con.InsertOne(inst.Name(), "", document); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *historyRepository) GetByIDAndDocument(ctx context.Context, ID, historyID string) (*model.History, error) {
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"must": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"document": ID,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"id": historyID,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"history_type": defs.HistoryTypeSystem,
					},
				},
			},
		},
	}

	var results model.History
	if err := inst.con.FindOne(inst.Name(), "", query, nil, &results); err != nil {
		return nil, err
	}

	return &results, nil
}
