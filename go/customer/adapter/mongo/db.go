package mongo

import "gitlab.viettelcyber.com/ti-micro/ws-customer/model"

type globalRepository struct {
	account  AccountRepository
	settings SettingsRepository
}

func (inst *globalRepository) Settings() SettingsRepository {
	//TODO implement me
	return inst.settings
}

func NewGlobalRepository(conf model.MongoConfig) GlobalRepository {
	// Success
	return &globalRepository{account: NewAccountRepository(conf.Account, conf.Database.TIAccount),
		settings: NewSettingsRepository(conf.Settings, conf.Database.Settings)}
}

func (inst *globalRepository) Account() AccountRepository {
	// Success
	return inst.account
}
