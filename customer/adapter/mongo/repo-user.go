package mongo

import (
	"context"
	"errors"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type userRepository struct {
	con      mongo.Database
	database string
}

func NewUserRepository(conf mongo.Config, database string) UserRepository {
	// Success
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}
	if database == "" {
		database = defs.DatabaseTIAccount
	}
	return &userRepository{con: con, database: database}
}

func (inst *userRepository) Name() (string, string) {
	// Success
	return inst.database, defs.CollectionUser
}

func (inst *userRepository) Get(ctx context.Context, name string) (*model.User, error) {
	filter := bson.M{}
	filter["$or"] = []interface{}{
		bson.M{"id": name},
		bson.M{"username": name},
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

func (inst *userRepository) GetByID(ctx context.Context, id string) (*model.User, error) {
	objID, _ := primitive.ObjectIDFromHex(id)
	filter := bson.M{"_id": objID}

	results, err := inst.Find(ctx, &filter, []string{}, 0, 1)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, errors.New(mongo.NotFoundError)
	}

	return results[0], nil
}

func (inst *userRepository) UpdateByID(ctx context.Context, id string, userUpdate *model.UpdatePublicUserDTO) error {
	database, collection := inst.Name()
	objID, _ := primitive.ObjectIDFromHex(id)
	update := bson.M{
		"$set": userUpdate,
	}
	err := inst.con.UpdateByID(database, collection, objID, update)
	if err != nil {
		return err
	}
	return nil
}

func (inst *userRepository) DeleteByID(ctx context.Context, id string) error {
	database, collection := inst.Name()
	objID, _ := primitive.ObjectIDFromHex(id)
	err := inst.con.DeleteByID(database, collection, objID)

	if err != nil {
		return err
	}
	return nil
}

func (inst *userRepository) Find(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.User, error) {
	if size == 0 {
		size = 10
	}
	database, collection := inst.Name()
	results := make([]*model.User, 0)
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

func (inst *userRepository) FindUsersV2(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.PublicUser, error) {
	if size == 0 {
		size = 10
	}
	database, collection := inst.Name()
	results := make([]*model.PublicUser, 0)
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
	return results, nil
}

func (inst *userRepository) CountUsersV2(ctx context.Context, query *bson.M) (int64, error) {
	database, collection := inst.Name()
	total, err := inst.con.Count(database, collection, query)
	if err != nil {
		return 0, err
	}
	return total, nil
}

type countResult struct {
	TwoFACounts []struct {
		ID    bool  `bson:"_id"`
		Count int64 `bson:"count"`
	} `bson:"twofaCounts"`

	RoleCounts []struct {
		ID    string `bson:"_id"`
		Count int64  `bson:"count"`
	} `bson:"roleCounts"`
}

func (inst *userRepository) GetFieldStats(ctx context.Context, query *bson.M) (*model.SearchStatisticResponseAggs, error) {
	database, collection := inst.Name()
	aggPipeline := []*bson.M{
		{"$match": query},
		{"$addFields": bson.M{
			"mfa_enabled": bson.M{
				"$anyElementTrue": bson.A{
					bson.M{
						"$map": bson.M{
							"input": bson.M{"$ifNull": bson.A{"$mfa_properties", bson.A{}}},
							"as":    "m",
							"in":    "$$m.enable",
						},
					},
				},
			},
		}},
		{"$facet": bson.M{
			"twofaCounts": createCountStage("mfa_enabled"),
			"roleCounts":  createCountStage("group_role"),
		}},
	}

	var rows []countResult
	if err := inst.con.Aggregate(database, collection, aggPipeline, &rows); err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return &model.SearchStatisticResponseAggs{}, nil
	}

	result := &model.SearchStatisticResponseAggs{}
	var roles []*model.AggStringFieldValue
	var otherRoleCount int64

	for _, r := range rows[0].RoleCounts {
		if r.ID == "admin" {
			roles = append(roles, &model.AggStringFieldValue{
				Value: r.ID,
				Count: r.Count,
			})
		} else {
			otherRoleCount += r.Count
		}
	}

	if otherRoleCount > 0 {
		roles = append(roles, &model.AggStringFieldValue{
			Value: "user",
			Count: otherRoleCount,
		})
	}

	result.Role = roles

	var twoFAs []*model.AggBoolFieldValue
	var notTrueCount int64

	for _, t := range rows[0].TwoFACounts {
		if t.ID {
			twoFAs = append(twoFAs, &model.AggBoolFieldValue{
				Value: t.ID,
				Count: t.Count,
			})
		} else {
			notTrueCount += t.Count
		}
	}

	if notTrueCount > 0 {
		twoFAs = append(twoFAs, &model.AggBoolFieldValue{
			Value: false,
			Count: notTrueCount,
		})
	}

	result.TwoFA = twoFAs

	return result, nil
}

func createCountStage(field string) []bson.M {
	stage := []bson.M{}
	stage = append(stage, bson.M{"$group": bson.M{"_id": "$" + field, "count": bson.M{"$sum": 1}}})
	return stage
}
