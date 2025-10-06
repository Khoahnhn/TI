package mongo

import "gitlab.viettelcyber.com/ti-micro/ws-threat/model"

type globalRepository struct {
	account      AccountRepository
	enduser      EnduserRepository
	threatReport ThreatReportRepository
}

func NewGlobalRepository(conf model.MongoConfig) GlobalRepository {
	// Success
	return &globalRepository{
		account:      NewAccountRepository(conf.Account),
		enduser:      NewEnduserRepository(conf.Enduser),
		threatReport: NewThreatReportRepository(conf.ThreatReport),
	}
}

func (inst *globalRepository) Account() AccountRepository {
	// Success
	return inst.account
}

func (inst *globalRepository) Enduser() EnduserRepository {
	// Success
	return inst.enduser
}

func (inst *globalRepository) ThreatReport() ThreatReportRepository {
	// Success
	return inst.threatReport
}
