package mongo

import (
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type brandabuseAlertRepository struct {
	con mg.Database
}

func NewBrandAbuseAlertRepository(conf mg.Config) BrandAbuseAlertRepository {
	con, err := mg.NewService(conf)
	if err != nil {
		panic(err)
	}
	// Success
	return &brandabuseAlertRepository{con: con}
}

func (inst *brandabuseAlertRepository) Name() (string, string) {
	// Success
	return defs.DbBrandAbuse, defs.ColAlert
}

func (inst *brandabuseAlertRepository) Find(query *bson.M, sorts []string, size, offset int64) ([]*model.BrandAbuseAlert, error) {
	database, collection := inst.Name()
	var results []*model.BrandAbuseAlert
	if _, err := inst.con.FindMany(database, collection, query, sorts, size, offset, &results); err != nil {
		return nil, err
	}
	// Success
	return results, nil
}

func (inst *brandabuseAlertRepository) FindAll(query *bson.M, sorts []string) ([]*model.BrandAbuseAlert, error) {
	database, collection := inst.Name()
	var results []*model.BrandAbuseAlert
	if _, err := inst.con.FindMany(database, collection, query, sorts, 0, 0, &results); err != nil {
		return nil, err
	}
	// Success
	return results, nil
}
