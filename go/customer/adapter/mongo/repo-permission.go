package mongo

import (
	"context"
	"errors"
	"time"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
)

type permissionsRepository struct {
	con mongo.Database
}

func NewPermissionsRepository(conf mongo.Config) PermissionsRepository {
	// Success
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}
	return &permissionsRepository{con: con}
}

func (inst *permissionsRepository) Name() (string, string) {
	// Success
	return defs.DatabaseTIAccount, defs.CollectionPermissions
}

func (inst *permissionsRepository) GetAll(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.Permissions, error) {
	database, collection := inst.Name()
	results := make([]*model.Permissions, 0)
	_, err := inst.con.FindMany(database, collection, query, sorts, offset, size, &results)
	if err != nil {
		return nil, err
	}
	// Success
	return results, nil
}

func (inst *permissionsRepository) CountPermissions(ctx context.Context, query *bson.M) (int64, error) {
	database, collection := inst.Name()
	total, err := inst.con.Count(database, collection, query)
	if err != nil {
		return 0, err
	}
	return total, nil
}

func (inst *permissionsRepository) UpdateByID(ctx context.Context, id string, doc *model.UpdatePermission) error {
	database, collection := inst.Name()
	now := time.Now().UnixMilli()
	update := bson.M{
		"$set": bson.M{
			"description":   doc.Description,
			"modified_time": now,
			"module_id":     doc.ModuleID,
		},
	}
	err := inst.con.UpdateByID(database, collection, id, update)
	if err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *permissionsRepository) UpdateFeature(ctx context.Context, request model.UpdateFeature) error {
	database, collection := inst.Name()
	query := &bson.M{
		"_id": bson.M{"$in": request.IDs},
	}
	now := time.Now().UnixMilli()
	update := bson.M{
		"$set": bson.M{
			"modified_time": now,
			"module_id":     request.FeatureID,
		},
	}
	err := inst.con.UpdateMany(database, collection, query, update, false)
	if err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *permissionsRepository) GetByPermissionID(ctx context.Context, permissions []string, offset, size int64) ([]*model.Permissions, error) {
	filter := bson.M{}
	filter["$or"] = bson.A{
		bson.M{"permission_id": bson.M{"$in": permissions}},
		bson.M{"_id": bson.M{"$in": permissions}},
	}
	results, err := inst.GetAll(ctx, &filter, []string{}, offset, size)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New(mongo.NotFoundError)
	}
	// Success
	return results, nil
}

func (inst *permissionsRepository) Aggregate(ctx context.Context, pipeline []*bson.M, result any) error {
	database, collection := inst.Name()
	// Success
	return inst.con.Aggregate(database, collection, pipeline, result)
}
