package mongo

import (
	"context"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
)

type groupSettingRepository struct {
	con mongo.Database
}

func (s *groupSettingRepository) Name() (string, string) {
	return defs.DatabaseTIAccount, defs.CollectionGroupSetting
}

func NewGroupSettingRepository(conf mongo.Config) GroupSettingRepository {
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}
	// Success
	return &groupSettingRepository{
		con: con,
	}
}

func (s *groupSettingRepository) GetGroupSetting(ctx context.Context, groupId string) ([]model.GroupSetting, error) {
	database, collection := s.Name()
	var settings []model.GroupSetting

	query := bson.M{"group_id": groupId}
	_, err := s.con.FindMany(
		database,
		collection,
		&query,
		nil,
		0,
		0,
		&settings,
	)
	if err != nil {
		return nil, err
	}

	return settings, nil
}
