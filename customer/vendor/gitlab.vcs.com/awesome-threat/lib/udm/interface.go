package udm

import "context"

type (
	repo interface {
		Name() string
	}
	Repository interface {
		repo
		Find(ctx context.Context, index string, query interface{}, sorts []string, offset, size int) ([]*Entity, error)
		FindAll(ctx context.Context, index string, query interface{}, sorts []string) ([]*Entity, error)
		Get(ctx context.Context, id string, kind EntityType) (*Entity, error)
		GetSourceRelationships(ctx context.Context, id string, kind EntityType, relationshipType RelationshipType, sorts []string, offset, size int) ([]*Entity, error)
		GetTargetRelationships(ctx context.Context, id string, kind EntityType, relationshipType RelationshipType, sorts []string, offset, size int) ([]*Entity, error)
		GetRelationships(ctx context.Context, id string, kind EntityType, relationshipType RelationshipType, sorts []string, offset, size int) ([]*Entity, error)
		InsertOne(ctx context.Context, document *Entity, kind EntityType) error
		Count(kind EntityType, query interface{}) (int64, error)
		CountSourceRelationships(id string, kind EntityType, relationshipType RelationshipType) (int64, error)
		CountTargetRelationships(id string, kind EntityType, relationshipType RelationshipType) (int64, error)
		CountRelationships(id string, kind EntityType, relationshipType RelationshipType) (int64, error)
	}
)
