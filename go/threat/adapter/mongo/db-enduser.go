package mongo

import mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"

type enduserRepository struct {
	brandabuse BrandAbuseRepository
}

func NewEnduserRepository(conf mg.Config) EnduserRepository {
	// Success
	return &enduserRepository{
		brandabuse: NewBrandAbuseRepository(conf),
	}
}

func (inst *enduserRepository) BrandAbuse() BrandAbuseRepository {
	// Success
	return inst.brandabuse
}
