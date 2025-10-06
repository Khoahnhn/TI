package mongo

import (
	"context"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
)

type userSettingRepository struct {
	con      mongo.Database
	database string
}

func (s userSettingRepository) GetUserSettings(ctx context.Context, username string) ([]model.UserSetting, error) {
	//TODO implement me
	database, collection := s.Name()
	var settings []model.UserSetting

	query := bson.M{"username": username}
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

func (s userSettingRepository) Name() (string, string) {
	//TODO implement me
	return defs.DatabaseTIAccount, defs.CollectionUserSetting
}

func NewUserSettingRepository(conf mongo.Config, database string) UserSettingRepository {
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}
	if database == "" {
		database = defs.DatabaseSettings
	}
	// Success
	return &userSettingRepository{
		con:      con,
		database: database,
	}
}
