package mongo

import mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"

type brandabuseRepository struct {
	alert BrandAbuseAlertRepository
}

func NewBrandAbuseRepository(conf mg.Config) BrandAbuseRepository {
	// Success
	return &brandabuseRepository{alert: NewBrandAbuseAlertRepository(conf)}
}

func (inst *brandabuseRepository) Alert() BrandAbuseAlertRepository {
	// Success
	return inst.alert
}
