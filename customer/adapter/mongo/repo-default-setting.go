package mongo

import (
	"context"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
)

type defaultSettingRepository struct {
	con mongo.Database
}

func NewDefaultSettingRepository(conf mongo.Config) DefaultSettingRepository {
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}

	return &defaultSettingRepository{
		con: con,
	}
}

func (r *defaultSettingRepository) Name() (string, string) {
	return defs.DatabaseTIAccount, defs.CollectionDefaultSetting
}

func (inst *defaultSettingRepository) GetDefaultSetting(ctx context.Context) (*model.DefaultConfig, error) {
	database, collection := inst.Name()
	var results []*model.DefaultConfig
	if _, err := inst.con.FindMany(
		database,
		collection,
		&bson.M{},
		[]string{},
		0,
		0,
		&results,
	); err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}
	// Success
	return results[0], nil
}
