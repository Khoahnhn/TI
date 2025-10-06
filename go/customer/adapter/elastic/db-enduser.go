package elastic

import (
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type enduserRepository struct {
	asset        AssetRepository
	assetHistory AssetHistoryRepository
}

func NewEnduserRepository(conf elastic.Config, indexConf model.ElasticIndexConfig) EnduserRepository {
	// Success
	return &enduserRepository{
		asset:        NewAssetRepository(conf, indexConf.TIAsset),
		assetHistory: NewAssetHistoryRepository(conf, indexConf.TIAssetHistory),
	}
}

func (inst *enduserRepository) Asset() AssetRepository {
	// Success
	return inst.asset
}

func (inst *enduserRepository) AssetHistory() AssetHistoryRepository {
	// Success
	return inst.assetHistory
}
