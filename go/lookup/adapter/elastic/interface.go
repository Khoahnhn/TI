package elastic

import (
	"context"

	"ws-lookup/model"

	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

type (
	repository interface {
		Name() string
	}

	GlobalRepository interface {
		UDM() UDMRepository
		Enrichment() EnrichmentRepository
	}

	UDMRepository interface {
		Object() UDMObjectRepository
	}

	EnrichmentRepository interface {
		CVE() CVERepository
		SetCVERepository(con CVERepository)
	}

	UDMObjectRepository interface {
		repository
		Get(entityID string, entityType udm.EntityType) (*udm.Entity, error)
		GetTargetRelationships(entityID string, entityType udm.EntityType, relationshipType udm.RelationshipType, sorts []string, size int, offset int) ([]*udm.Entity, error)
		CountTargetRelationships(entityID string, entityType udm.EntityType, relationshipType udm.RelationshipType) (int64, error)
		FindByValue(value string) ([]*udm.Entity, error)
		InsertOne(doc *udm.Entity, entityType udm.EntityType) error
		SetDbCon(con udm.Repository)
	}

	CVERepository interface {
		repository
		Find(ctx context.Context, index string, query interface{}, sorts []string, offset, size int) ([]*model.CVE, error)
		FindAll(ctx context.Context, query interface{}, sorts []string) ([]*model.CVE, error)
		FindByValues(values []string) ([]*model.CVE, error)
	}
)
