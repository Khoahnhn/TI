package elastic

import (
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type globalRepository struct {
	enduser    EnduserRepository
	enrichment EnrichmentRepository
}

func NewGlobalRepository(config model.ElasticConfig) GlobalRepository {
	// Success
	return &globalRepository{
		enduser:    NewEnduserRepository(config.Enduser),
		enrichment: NewEnrichmentRepository(config.Enrichment),
	}
}

func (inst *globalRepository) Enduser() EnduserRepository {
	// Success
	return inst.enduser
}

func (inst *globalRepository) Enrichment() EnrichmentRepository {
	// Success
	return inst.enrichment
}
