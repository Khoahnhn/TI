package udm

import (
	"fmt"
)

type Relationship struct {
	SourceEntityID    string           `json:"source_entity_id,omitempty"`
	SourceEntityType  EntityType       `json:"source_entity_type,omitempty"`
	TargetEntityID    string           `json:"target_entity_id,omitempty"`
	TargetEntityType  EntityType       `json:"target_entity_type,omitempty"`
	RelationshipLabel string           `json:"relationship_label,omitempty"`
	Direction         Directionality   `json:"direction,omitempty"`
	RelationshipType  RelationshipType `json:"relationship_type,omitempty"`
}

func NewRelationship(source, target *Entity, relationshipType RelationshipType, relationshipLabel string, direction Directionality) *Entity {
	value := fmt.Sprintf("%s--%s--%s--%s--%s", source.GetID(), source.GetType(), relationshipType, target.GetID(), target.GetType())
	entity := NewEntity(value, EntityTypeRelationship)
	entity.Noun.Relationship.SourceEntityID = source.GetID()
	entity.Noun.Relationship.SourceEntityType = source.GetType()
	entity.Noun.Relationship.RelationshipType = relationshipType
	entity.Noun.Relationship.RelationshipLabel = relationshipLabel
	entity.Noun.Relationship.Direction = direction
	entity.Noun.Relationship.TargetEntityID = target.GetID()
	entity.Noun.Relationship.TargetEntityType = target.GetType()
	// Success
	return entity
}
