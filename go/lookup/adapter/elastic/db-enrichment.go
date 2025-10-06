package elastic

import "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"

type enrichmentRepository struct {
	cve CVERepository
}

func NewEnrichmentRepository(conf elastic.Config) EnrichmentRepository {
	// Success
	return &enrichmentRepository{cve: NewCVERepository(conf)}
}

func (inst *enrichmentRepository) CVE() CVERepository {
	// Success
	return inst.cve
}

func (inst *enrichmentRepository) SetCVERepository(con CVERepository) {
	inst.cve = con
}
