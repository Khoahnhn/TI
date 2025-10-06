package udm

import (
	"context"
	"errors"
	"fmt"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
)

type repository struct {
	con elastic.Service
}

func NewRepository(conf elastic.Config) Repository {
	service := elastic.NewService(conf)
	// Success
	return &repository{con: service}
}

func (inst *repository) Name() string {
	// Success
	return IndexUDM
}

func (inst *repository) Find(ctx context.Context, index string, query interface{}, sorts []string, offset, size int) ([]*Entity, error) {
	if size == 0 {
		size = 10
	}
	results := make([]*Entity, 0)
	_, err := inst.con.FindOffset(
		index,
		"",
		query.(map[string]interface{}),
		sorts,
		offset,
		size,
		&results)
	if err != nil {
		return nil, err
	}
	// Success
	return results, nil
}

func (inst *repository) FindAll(ctx context.Context, index string, query interface{}, sorts []string) ([]*Entity, error) {
	size := 0
	offset := 0
	if value := ctx.Value("size"); value != nil {
		size = value.(int)
	}
	if size == 0 {
		size = 100
	}
	if value := ctx.Value("offset"); value != nil {
		offset = value.(int)
	}
	results := make([]*Entity, 0)
	results, err := inst.Find(ctx, index, query, sorts, offset, size)
	if err != nil || len(results) == 0 {
		return results, err
	}
	// Recursive
	ctx = context.WithValue(ctx, "size", size)
	ctx = context.WithValue(ctx, "offset", offset+size)
	recursiveResults, err := inst.FindAll(ctx, index, query, sorts)
	if err != nil || len(recursiveResults) == 0 {
		return results, nil
	}
	// Success
	return append(results, recursiveResults...), nil
}

func (inst *repository) Get(ctx context.Context, id string, kind EntityType) (*Entity, error) {
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"metadata.id": id,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"metadata.entity_type": kind,
					},
				},
			},
		},
	}
	index := fmt.Sprintf(inst.Name(), kind)
	if kind == "" {
		index = fmt.Sprintf(inst.Name(), "*")
	}
	res, err := inst.Find(ctx, index, query, []string{}, 0, 1)
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, errors.New(elastic.NotFoundError)
	}
	// Success
	return res[0], nil
}

func (inst *repository) GetSourceRelationships(ctx context.Context, id string, kind EntityType, relationshipType RelationshipType, sorts []string, offset, size int) ([]*Entity, error) {
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.target_entity_id": id,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.target_entity_type": kind,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.relationship_type": relationshipType,
					},
				},
			},
		},
	}
	// Success
	return inst.Find(ctx, fmt.Sprintf(inst.Name(), "relationship"), query, sorts, offset, size)
}

func (inst *repository) GetTargetRelationships(ctx context.Context, id string, kind EntityType, relationshipType RelationshipType, sorts []string, offset, size int) ([]*Entity, error) {
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.source_entity_id": id,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.source_entity_type": kind,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.relationship_type": relationshipType,
					},
				},
			},
		},
	}
	// Success
	return inst.Find(ctx, fmt.Sprintf(inst.Name(), "relationship"), query, sorts, offset, size)
}

func (inst *repository) GetRelationships(ctx context.Context, id string, kind EntityType, relationshipType RelationshipType, sorts []string, offset, size int) ([]*Entity, error) {
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.relationship_type": relationshipType,
					},
				},
			},
			"should": []interface{}{
				map[string]interface{}{
					"bool": map[string]interface{}{
						"filter": []interface{}{
							map[string]interface{}{
								"term": map[string]interface{}{
									"noun.relationship.target_entity_id": id,
								},
							},
							map[string]interface{}{
								"term": map[string]interface{}{
									"noun.relationship.target_entity_type": kind,
								},
							},
						},
					},
				},
				map[string]interface{}{
					"bool": map[string]interface{}{
						"filter": []interface{}{
							map[string]interface{}{
								"term": map[string]interface{}{
									"noun.relationship.source_entity_id": id,
								},
							},
							map[string]interface{}{
								"term": map[string]interface{}{
									"noun.relationship.source_entity_type": kind,
								},
							},
						},
					},
				},
			},
		},
	}
	// Success
	return inst.Find(ctx, fmt.Sprintf(inst.Name(), "relationship"), query, sorts, offset, size)
}

func (inst *repository) InsertOne(ctx context.Context, document *Entity, kind EntityType) error {
	if err := inst.con.InsertOne(fmt.Sprintf(inst.Name(), kind), "", document); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *repository) Count(kind EntityType, query interface{}) (int64, error) {
	count, err := inst.con.Count(fmt.Sprintf(inst.Name(), kind), "", query.(map[string]interface{}))
	if err != nil {
		return 0, err
	}
	// Success
	return count, nil
}

func (inst *repository) CountSourceRelationships(id string, kind EntityType, relationshipType RelationshipType) (int64, error) {
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.target_entity_id": id,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.target_entity_type": kind,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.relationship_type": relationshipType,
					},
				},
			},
		},
	}
	count, err := inst.Count(EntityTypeRelationship, query)
	if err != nil {
		return 0, err
	}
	// Success
	return count, nil
}

func (inst *repository) CountTargetRelationships(id string, kind EntityType, relationshipType RelationshipType) (int64, error) {
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.source_entity_id": id,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.source_entity_type": kind,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.relationship_type": relationshipType,
					},
				},
			},
		},
	}
	count, err := inst.Count(EntityTypeRelationship, query)
	if err != nil {
		return 0, err
	}
	// Success
	return count, nil
}

func (inst *repository) CountRelationships(id string, kind EntityType, relationshipType RelationshipType) (int64, error) {
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"noun.relationship.relationship_type": relationshipType,
					},
				},
			},
			"should": []interface{}{
				map[string]interface{}{
					"bool": map[string]interface{}{
						"filter": []interface{}{
							map[string]interface{}{
								"term": map[string]interface{}{
									"noun.relationship.target_entity_id": id,
								},
							},
							map[string]interface{}{
								"term": map[string]interface{}{
									"noun.relationship.target_entity_type": kind,
								},
							},
						},
					},
				},
				map[string]interface{}{
					"bool": map[string]interface{}{
						"filter": []interface{}{
							map[string]interface{}{
								"term": map[string]interface{}{
									"noun.relationship.source_entity_id": id,
								},
							},
							map[string]interface{}{
								"term": map[string]interface{}{
									"noun.relationship.source_entity_type": kind,
								},
							},
						},
					},
				},
			},
		},
	}
	count, err := inst.Count(EntityTypeRelationship, query)
	if err != nil {
		return 0, err
	}
	// Success
	return count, nil
}
