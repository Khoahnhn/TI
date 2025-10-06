package mongo

import (
	"context"
	"errors"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type groupUserRepository struct {
	con      mongo.Database
	database string
}

func NewGroupUserRepository(conf mongo.Config, database string) GroupUserRepository {
	// Success
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}
	if database == "" {
		database = defs.DatabaseTIAccount
	}
	return &groupUserRepository{con: con, database: database}
}

func (inst *groupUserRepository) Name() (string, string) {
	// Success
	return inst.database, defs.CollectionGroupUser
}

func (inst *groupUserRepository) Get(ctx context.Context, name string) (*model.GroupUser, error) {
	filter := bson.M{}
	filter["$or"] = []interface{}{
		bson.M{"_id": name},
		bson.M{"tenant_id": name},
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

func (inst *groupUserRepository) GetByID(ctx context.Context, id string) (*model.GroupUser, error) {
	database, collection := inst.Name()
	var result model.GroupUser
	if err := inst.con.Get(database, collection, id, &result); err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (inst *groupUserRepository) GetByRole(ctx context.Context, role string) (*model.GroupUser, error) {
	filter := bson.M{
		"role": role,
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

func (inst *groupUserRepository) Find(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.GroupUser, error) {
	if size == 0 {
		size = 10
	}
	database, collection := inst.Name()
	results := make([]*model.GroupUser, 0)
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

func (inst *groupUserRepository) FindAll(ctx context.Context, query *bson.M, sorts []string) ([]*model.GroupUser, error) {
	database, collection := inst.Name()
	var results []*model.GroupUser
	if _, err := inst.con.FindMany(
		database,
		collection,
		query,
		sorts,
		0,
		0,
		&results,
	); err != nil {
		return nil, err
	}
	// Success
	return results, nil
}

func (inst *groupUserRepository) GetOrg(ctx context.Context, id string, isActive *bool) (*model.Organization, error) {
	filter := bson.M{}
	if isActive != nil {
		filter["active"] = isActive
	}
	filter["$or"] = []interface{}{
		bson.M{"_id": id},
		bson.M{"tenant_id": id},
	}
	database, collection := inst.Name()
	var result model.Organization
	err := inst.con.FindOne(
		database,
		collection,
		&filter,
		[]string{},
		0,
		&result)
	if err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (inst *groupUserRepository) Count(ctx context.Context, query *bson.M) (int64, error) {
	database, collection := inst.Name()
	// Success
	return inst.con.Count(database, collection, query)
}

func (inst *groupUserRepository) RunAggPipeline(ctx context.Context, pipeline []*bson.M, result any) error {
	database, collection := inst.Name()
	return inst.con.Aggregate(database, collection, pipeline, result)
}

func (inst *groupUserRepository) InsertOrg(ctx context.Context, org *model.Organization) error {
	database, collection := inst.Name()
	return inst.con.InsertOne(database, collection, org)
}

func (inst *groupUserRepository) UpdateOrg(ctx context.Context, org *model.Organization) error {
	database, collection := inst.Name()
	return inst.con.UpdateByID(database, collection, org.Id, bson.M{"$set": org})
}

func (inst *groupUserRepository) UpdateMany(ctx context.Context, query bson.M, update bson.A, upsert bool) error {
	database, collection := inst.Name()
	return inst.con.UpdateMany(database, collection, &query, update, upsert)
}

func (inst *groupUserRepository) FindAllOrgs(ctx context.Context, query *bson.M, sorts []string) ([]*model.Organization, error) {
	database, collection := inst.Name()
	var results []*model.Organization
	if _, err := inst.con.FindMany(
		database,
		collection,
		query,
		sorts,
		0,
		0,
		&results,
	); err != nil {
		return nil, err
	}
	// Success
	return results, nil
}
