package mongo

import (
	"context"
	"errors"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
)

type featuresRepository struct {
	con mongo.Database
}

func NewFeaturesRepository(conf mongo.Config) FeaturesRepository {
	// Success
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}
	if err = con.CreateIndex(defs.DatabaseTIAccount, defs.CollectionFeatures, &bson.M{
		"code": -1,
	}, true); err != nil {
		panic(err)
	}
	return &featuresRepository{con: con}
}

func (inst *featuresRepository) Name() (string, string) {
	// Success
	return defs.DatabaseTIAccount, defs.CollectionFeatures
}

func (inst *featuresRepository) Store(ctx context.Context, doc *model.Feature) error {
	database, collection := inst.Name()
	if err := inst.con.InsertOne(database, collection, doc); err != nil {
		return err
	}
	return nil
}

func (inst *featuresRepository) FindMany(ctx context.Context, query *bson.M) ([]*model.Feature, error) {
	database, collection := inst.Name()
	results := make([]*model.Feature, 0)
	_, err := inst.con.FindMany(database, collection, query, []string{}, 0, 0, &results)
	if err != nil {
		return nil, err
	}
	// Success
	return results, nil
}

func (inst *featuresRepository) Find(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.Feature, error) {
	if size == 0 {
		size = 10
	}
	database, collection := inst.Name()
	results := make([]*model.Feature, 0)
	_, err := inst.con.FindMany(
		database,
		collection,
		query,
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

func (inst *featuresRepository) GetByName(ctx context.Context, name string) (*model.Feature, error) {
	filter := bson.M{}
	filter["$or"] = bson.A{
		bson.M{"_id": name},
		bson.M{"name": name},
		bson.M{"code": name},
	}
	results, err := inst.Find(ctx, &filter, []string{}, 0, 1)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New(mongo.NotFoundError)
	}
	// Success
	return results[0], nil
}

func (inst *featuresRepository) Aggregate(ctx context.Context, pipeline []*bson.M, result any) error {
	database, collection := inst.Name()
	// Success
	return inst.con.Aggregate(database, collection, pipeline, result)
}

func (inst *featuresRepository) UpdateByID(ctx context.Context, id string, document *model.Feature) error {
	database, collection := inst.Name()
	updateData := bson.M{
		"$set": bson.M{
			"editor":      document.Editor,
			"updated_at":  document.UpdatedAt,
			"weight":      document.Weight,
			"parent_id":   document.ParentID,
			"ancestors":   document.Ancestors,
			"description": document.Description,
			"name":        document.Name,
			"actions":     document.Actions,
		},
	}
	err := inst.con.UpdateByID(database, collection, id, updateData)
	if err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *featuresRepository) Count(ctx context.Context, query *bson.M) (int64, error) {
	database, collection := inst.Name()
	// Success
	return inst.con.Count(database, collection, query)
}

func (inst *featuresRepository) GetByCode(ctx context.Context, code []string, offset, size int64) ([]*model.Feature, error) {
	filter := bson.M{}
	filter["$or"] = bson.A{
		bson.M{"code": bson.M{"$in": code}},
		bson.M{"_id": bson.M{"$in": code}},
	}
	results, err := inst.Find(ctx, &filter, []string{}, offset, size)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New(mongo.NotFoundError)
	}
	// Success
	return results, nil
}
