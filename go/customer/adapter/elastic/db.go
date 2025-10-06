package elastic

import "gitlab.viettelcyber.com/ti-micro/ws-customer/model"

type globalRepository struct {
	enduser EnduserRepository
}

func NewGlobalRepository(conf model.ElasticConfig) GlobalRepository {
	// Success
	return &globalRepository{enduser: NewEnduserRepository(conf.Enduser, conf.Index)}
}

func (inst *globalRepository) Enduser() EnduserRepository {
	// Success
	return inst.enduser
}
