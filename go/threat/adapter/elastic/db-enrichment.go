package elastic

import (
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

type enrichmentRepository struct {
	cve             CVERepository
	cveRaw          CVERawRepository
	cveLang         CVELangRepository
	cveHistory      HistoryRepository
	cpe             CPERepository
	cpePopular      CPEPopularRepository
	ioc             IOCRepository
	iocHistory      IOCHistoryRepository
	udm             udm.Repository
	cveLifecycle    CVELifecycleRepository
	cveEpssHistory  CVEEPSSHistoryRepository
	cveLifeCycleV2  CVELifeCycleV2Repository
	cveInternalFlag CVEInternalFlagRepository
	cveCustomer     CVECustomerRepository
}

func NewEnrichmentRepository(conf elastic.Config) EnrichmentRepository {
	return &enrichmentRepository{
		cve:             NewCVERepository(conf),
		cveRaw:          NewCVERawRepository(conf),
		cveLang:         NewCVELangRepository(conf),
		cveHistory:      NewHistoryRepository(conf),
		cpe:             NewCPERepository(conf),
		cpePopular:      NewCPEPopularRepository(conf),
		ioc:             NewIOCRepository(conf),
		iocHistory:      NewIOCHistoryRepository(conf),
		udm:             udm.NewRepository(conf),
		cveLifecycle:    NewCVELifecycleRepository(conf),
		cveEpssHistory:  NewCVEEPSSHistoryRepository(conf),
		cveLifeCycleV2:  NewCVELifeCycleV2Repository(conf),
		cveInternalFlag: NewCVEInternalFlagRepository(conf),
		cveCustomer:     NewCVECustomerRepository(conf),
	}
}

func (inst *enrichmentRepository) CVE() CVERepository {
	// Success
	return inst.cve
}

func (inst *enrichmentRepository) CVERaw() CVERawRepository {
	// Success
	return inst.cveRaw
}

func (inst *enrichmentRepository) CVELang(lang string) CVELangRepository {
	inst.cveLang.SetLanguage(lang)
	// Success
	return inst.cveLang
}

func (inst *enrichmentRepository) CVEHistory() HistoryRepository {
	// Success
	return inst.cveHistory
}

func (inst *enrichmentRepository) CPE() CPERepository {
	// Success
	return inst.cpe
}

func (inst *enrichmentRepository) CPEPopular() CPEPopularRepository {
	// Success
	return inst.cpePopular
}

func (inst *enrichmentRepository) IOC() IOCRepository {
	// Success
	return inst.ioc
}

func (inst *enrichmentRepository) IOCHistory() IOCHistoryRepository {
	// Success
	return inst.iocHistory
}

func (inst *enrichmentRepository) UDM() udm.Repository {
	// Success
	return inst.udm
}

func (inst *enrichmentRepository) CVELifecycle() CVELifecycleRepository {
	return inst.cveLifecycle
}

func (inst *enrichmentRepository) CVEEPSSHistory() CVEEPSSHistoryRepository {
	return inst.cveEpssHistory
}

func (inst *enrichmentRepository) CVELifeCycleV2() CVELifeCycleV2Repository {
	return inst.cveLifeCycleV2
}

func (inst *enrichmentRepository) CVEInternalFlag() CVEInternalFlagRepository {
	return inst.cveInternalFlag
}

func (inst *enrichmentRepository) CVECustomer() CVECustomerRepository {
	return inst.cveCustomer
}
