package elastic

import "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"

type enduserRepository struct {
	asset        AssetRepository
	ttiAlert     TTIAlertRepository
	ttiEvent     TTIEventRepository
	intelligence TIIntelligenceRepository
	delivery     TIDeliveryRepository
}

func NewEnduserRepository(conf elastic.Config) EnduserRepository {
	// Success
	return &enduserRepository{
		asset:        NewAssetRepository(conf),
		ttiAlert:     NewTTIAlertRepository(conf),
		ttiEvent:     NewTTIEventRepository(conf),
		intelligence: NewTIIntelligenceRepository(conf),
		delivery:     NewTIDeliveryRepository(conf),
	}
}

func (inst *enduserRepository) Asset() AssetRepository {
	// Success
	return inst.asset
}

func (inst *enduserRepository) TTIAlert() TTIAlertRepository {
	// Success
	return inst.ttiAlert
}

func (inst *enduserRepository) TTIEvent() TTIEventRepository {
	// Success
	return inst.ttiEvent
}

func (inst *enduserRepository) Intelligence() TIIntelligenceRepository {
	// Success
	return inst.intelligence
}

func (inst *enduserRepository) Delivery() TIDeliveryRepository {
	// Success
	return inst.delivery
}
