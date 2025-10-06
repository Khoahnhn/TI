package elastic

import (
	"context"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic/db"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type (
	repository interface {
		Name() string
	}

	GlobalRepository interface {
		Enduser() EnduserRepository
	}

	EnduserRepository interface {
		Asset() AssetRepository
		AssetHistory() AssetHistoryRepository
	}

	AssetRepository interface {
		repository
		GetByID(ctx context.Context, id string) (*model.Asset, error)
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.Asset, error)
		FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.Asset, error)
		Count(ctx context.Context, query interface{}) (int64, error)
		Store(ctx context.Context, document *model.Asset) error
		StoreAll(ctx context.Context, documents []*model.Asset) error
		Update(ctx context.Context, document *model.Asset) error
		DeleteByID(ctx context.Context, id string) error
		AggregationCount(ctx context.Context, query interface{}, fields []string) (map[string][]db.ResultAggregationCount, error)
	}

	AssetHistoryRepository interface {
		repository
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.AssetHistory, error)
		FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.AssetHistory, error)
		Count(ctx context.Context, query interface{}) (int64, error)
		Store(ctx context.Context, document *model.AssetHistory) error
		StoreAll(ctx context.Context, documents []*model.AssetHistory) error
		DeleteByID(ctx context.Context, id string) error
	}
)
