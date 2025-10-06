package elastic

import (
	"context"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type (
	repositoryV7 interface {
		Name() string
	}

	GlobalRepository interface {
		Enduser() EnduserRepository
		Enrichment() EnrichmentRepository
	}

	TIIntelligenceRepository interface {
		repositoryV7
		GetByID(ctx context.Context, id string) (*model.Intelligence, error)
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.Intelligence, error)
		FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.Intelligence, error)
	}

	TIDeliveryRepository interface {
		repositoryV7
		GetByID(ctx context.Context, id string) (*model.Delivery, error)
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.Delivery, error)
		FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.Delivery, error)
	}

	EnduserRepository interface {
		Asset() AssetRepository
		TTIAlert() TTIAlertRepository
		TTIEvent() TTIEventRepository
		Intelligence() TIIntelligenceRepository
		Delivery() TIDeliveryRepository
	}

	TTIAlertRepository interface {
		repositoryV7
		Find(ctx context.Context, org string, query interface{}, sorts []string, offset, size int) ([]*model.TTIAlert, error)
		FindAll(ctx context.Context, org string, query interface{}, sorts []string) ([]*model.TTIAlert, error)
	}

	TTIEventRepository interface {
		repositoryV7
		GetByID(ctx context.Context, org, id string) (*model.TTIEvent, error)
		Find(ctx context.Context, org string, query interface{}, sorts []string, offset, size int) ([]*model.TTIEvent, error)
		FindAll(ctx context.Context, org string, query interface{}, sorts []string) ([]*model.TTIEvent, error)
	}

	EnrichmentRepository interface {
		CVE() CVERepository
		CVERaw() CVERawRepository
		CVEHistory() HistoryRepository
		CVELang(lang string) CVELangRepository
		CPE() CPERepository
		CPEPopular() CPEPopularRepository
		IOC() IOCRepository
		IOCHistory() IOCHistoryRepository
		UDM() udm.Repository
		CVELifecycle() CVELifecycleRepository
		CVEEPSSHistory() CVEEPSSHistoryRepository
		CVELifeCycleV2() CVELifeCycleV2Repository
		CVEInternalFlag() CVEInternalFlagRepository
		CVECustomer() CVECustomerRepository
	}

	CVERepository interface {
		repositoryV7
		GetByID(ctx context.Context, id string) (*model.CVE, error)
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.CVE, error)
		Count(ctx context.Context, query interface{}) (int64, error)
		Store(ctx context.Context, document *model.CVE) error
		AggregationCount(ctx context.Context, query interface{}, fields []string) (map[string][]elastic.ResultAggregationCount, error)
		AggregationCountWithSize(ctx context.Context, query interface{}, fields map[string]int) (map[string][]elastic.ResultAggregationCount, error)
	}

	CVELifecycleRepository interface {
		repositoryV7
		Store(ctx context.Context, document *model.CVELifecycle) error
	}

	CVERawRepository interface {
		repositoryV7
		GetByID(ctx context.Context, id string) (*model.CVERaw, error)
	}

	CVELangRepository interface {
		repositoryV7
		SetLanguage(lang string)
		GetByID(ctx context.Context, id string) (*model.CVELang, error)
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.CVELang, error)
		FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.CVELang, error)
		FindByID(ctx context.Context, id string) ([]*model.CVELang, error)
		Store(ctx context.Context, document *model.CVELang) error
	}

	HistoryRepository interface {
		repositoryV7
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.History, int64, error)
		GetByIDAndDocument(ctx context.Context, id, historyId string) (*model.History, error)
		FindByDocument(ctx context.Context, id string, sorts []string, offset, size int) ([]*model.History, int64, error)
		Count(ctx context.Context, query interface{}) (int64, error)
		Store(ctx context.Context, document *model.History) error
	}

	CVEEPSSHistoryRepository interface {
		repositoryV7
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.CVEEPSSHistory, int64, error)
		FindByCVEName(ctx context.Context, cveName string, sorts []string, offset, size int) ([]*model.CVEEPSSHistory, int64, error)
		Count(ctx context.Context, query interface{}) (int64, error)
		Store(ctx context.Context, document *model.CVEEPSSHistory) error
	}

	CVELifeCycleV2Repository interface {
		repositoryV7
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.CVELifeCycleV2, int64, error)
		Count(ctx context.Context, query interface{}) (int64, error)
		Store(ctx context.Context, document *model.CVELifeCycleV2) error
		StoreBulk(ctx context.Context, documents []*model.CVELifeCycleV2) error
		FindBulk(ctx context.Context, value []string) ([]*model.CVELifeCycleV2, error)
		Update(ctx context.Context, document *model.CVELifeCycleV2) error
	}

	CVEInternalFlagRepository interface {
		repositoryV7
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.CVEInternalFlag, int64, error)
		Store(ctx context.Context, document *model.CVEInternalFlag) error
		StoreAll(ctx context.Context, documents []*model.CVEInternalFlag) error
	}

	CPERepository interface {
		repositoryV7
		GetByID(ctx context.Context, id string) (*model.CPE, error)
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.CPE, error)
		FindByValue(ctx context.Context, value string) (*model.CPE, error)
		FindCollapse(ctx context.Context, query interface{}, sorts []string, field string, offset, size int) ([]*model.CPE, error)
		FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.CPE, error)
		Count(ctx context.Context, query interface{}) (int64, error)
		Store(ctx context.Context, document *model.CPE) error
		DeleteByID(ctx context.Context, id string) error
		AggregationCount(ctx context.Context, query interface{}, fields []string) (map[string][]elastic.ResultAggregationCount, error)
	}

	CPEPopularRepository interface {
		repositoryV7
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.CPEPopular, error)
		FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.CPEPopular, error)
		Count(ctx context.Context, query interface{}) (int64, error)
		GetByID(ctx context.Context, id string) (*model.CPEPopular, error)
		Store(ctx context.Context, document *model.CPEPopular) error
		DeleteByID(ctx context.Context, id string) error
		AggregationCount(ctx context.Context, query interface{}, fields []string) (map[string][]elastic.ResultAggregationCount, error)
	}

	IOCRepository interface {
		repositoryV7
		GetByID(ctx context.Context, index, id string) (*model.IOC, error)
		FindByID(ctx context.Context, id string) (*model.IOC, error)
		Find(ctx context.Context, index string, query interface{}, sorts []string, offset, size int) ([]*model.IOC, error)
		FindAll(ctx context.Context, index string, query interface{}, sorts []string) ([]*model.IOC, error)
		Count(ctx context.Context, index string, query interface{}) (int64, error)
		StoreAll(ctx context.Context, documents []*model.IOC) error
		Update(ctx context.Context, index string, document *model.IOC) error
		AggregationCount(ctx context.Context, index string, query interface{}, fields []string) (map[string][]elastic.ResultAggregationCount, error)
		AggregationTopHits(ctx context.Context, index string, query interface{}, field string, size int) ([]string, error)
	}

	IOCHistoryRepository interface {
		repositoryV7
		FindByIOCID(ctx context.Context, id string) ([]*model.IOCHistory, error)
		Find(ctx context.Context, index string, query interface{}, sorts []string, offset, size int) ([]*model.IOCHistory, error)
		FindAll(ctx context.Context, index string, query interface{}, sorts []string) ([]*model.IOCHistory, error)
		Store(ctx context.Context, document *model.IOCHistory) error
		StoreAll(ctx context.Context, documents []*model.IOCHistory) error
	}

	AssetRepository interface {
		repositoryV7
		GetByID(ctx context.Context, id string) (*model.Asset, error)
		Find(ctx context.Context, query interface{}, sorts []string, offset, size int) ([]*model.Asset, error)
		FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.Asset, error)
	}

	UDMRepository interface {
		repositoryV7
	}

	CVECustomerRepository interface {
		repositoryV7
		BulkInsert(ctx context.Context, docs []*model.CveCustomer) error
		BulkDelete(ctx context.Context, query any) error
		Find(ctx context.Context, query interface{}) ([]*model.CveCustomer, error)
	}
)
