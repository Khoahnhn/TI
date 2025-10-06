package elastic

import "ws-lookup/model"

type globalRepository struct {
	enrichment EnrichmentRepository
	udm        UDMRepository
}

func NewGlobalRepository(conf model.ElasticConfig) GlobalRepository {
	// Success
	return &globalRepository{
		enrichment: NewEnrichmentRepository(conf.Enrichment),
		udm:        NewUDMRepository(conf.UDM),
	}
}

func (inst *globalRepository) Enrichment() EnrichmentRepository {
	// Success
	return inst.enrichment
}

func (inst *globalRepository) UDM() UDMRepository {
	// Success
	return inst.udm
}
