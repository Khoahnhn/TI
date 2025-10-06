package mongo

import (
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type ttiConfigurationRepository struct {
	con mg.Database
}

func NewAccountConfigurationRepository(conf mg.Config) AccountConfigurationRepository {
	con, err := mg.NewService(conf)
	if err != nil {
		panic(err)
	}
	// Success
	return &ttiConfigurationRepository{con: con}
}

func (inst *ttiConfigurationRepository) Name() (string, string) {
	// Success
	return defs.DbTIAccount, defs.ColConfiguration
}

func (inst *ttiConfigurationRepository) FindOne(query *bson.M, sorts []string, offset int64) (*model.TTIConfig, error) {
	database, collection := inst.Name()
	var result model.TTIConfig
	if err := inst.con.FindOne(database, collection, query, sorts, offset, &result); err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (inst *ttiConfigurationRepository) GetConfig() (*model.TTIConfig, error) {
	// Success
	return inst.FindOne(&bson.M{}, []string{}, 0)
}
