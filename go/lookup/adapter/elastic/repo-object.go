package elastic

import (
	"context"
	"fmt"
	"time"

	"ws-lookup/defs"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

type udmObjectRepository struct {
	con udm.Repository
}

func NewUDMObjectRepository(conf elastic.Config) UDMObjectRepository {
	if conf.Address == "" {
		return &udmObjectRepository{}
	}
	// Success
	return &udmObjectRepository{con: udm.NewRepository(conf)}
}

func (inst *udmObjectRepository) Name() string {
	// Success
	return udm.IndexUDM
}

func (inst *udmObjectRepository) FindByValue(value string) ([]*udm.Entity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defs.DefaultDbTimeout*time.Second)
	defer cancel()
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"metadata.value": value,
					},
				},
			},
		},
	}
	docs, err := inst.con.FindAll(ctx, fmt.Sprintf(inst.Name(), "*"), query, []string{"-metadata.creation_timestamp"})
	if err != nil {
		if err.Error() == defs.ErrNotFound {
			return make([]*udm.Entity, 0), nil
		}
		return nil, err
	}
	// Success
	return docs, nil
}

func (inst *udmObjectRepository) Get(entityID string, entityType udm.EntityType) (*udm.Entity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defs.DefaultDbTimeout*time.Second)
	defer cancel()
	doc, err := inst.con.Get(ctx, entityID, entityType)
	if err != nil {
		if err.Error() == defs.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	// Success
	return doc, nil
}

func (inst *udmObjectRepository) GetTargetRelationships(entityID string, entityType udm.EntityType, relationshipType udm.RelationshipType, sorts []string, size int, offset int) ([]*udm.Entity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defs.DefaultDbTimeout*time.Second)
	defer cancel()
	if len(sorts) == 0 {
		sorts = []string{"-metadata.valid_from_timestamp"}
	}
	docs, err := inst.con.GetTargetRelationships(ctx, entityID, entityType, relationshipType, sorts, offset, size)
	if err != nil {
		if err.Error() == defs.ErrNotFound {
			return make([]*udm.Entity, 0), nil
		}
		return nil, err
	}
	// Success
	return docs, nil
}

func (inst *udmObjectRepository) CountTargetRelationships(entityID string, entityType udm.EntityType, relationshipType udm.RelationshipType) (int64, error) {
	count, err := inst.con.CountTargetRelationships(entityID, entityType, relationshipType)
	if err != nil {
		return 0, err
	}
	// Success
	return count, nil
}

func (inst *udmObjectRepository) InsertOne(doc *udm.Entity, entityType udm.EntityType) error {
	ctx, cancel := context.WithTimeout(context.Background(), defs.DefaultDbTimeout*time.Second)
	defer cancel()
	if err := inst.con.InsertOne(ctx, doc, entityType); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *udmObjectRepository) SetDbCon(con udm.Repository) {
	// Success
	inst.con = con
}
