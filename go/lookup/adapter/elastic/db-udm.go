package elastic

import (
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
)

type udmRepository struct {
	object UDMObjectRepository
}

func NewUDMRepository(conf elastic.Config) UDMRepository {
	// Success
	return &udmRepository{
		object: NewUDMObjectRepository(conf),
	}
}

func (inst *udmRepository) Object() UDMObjectRepository {
	// Success
	return inst.object
}
