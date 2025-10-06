package mongo

import (
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type accountSupportRepository struct {
	con mg.Database
}

func NewAccountSupportRepository(conf mg.Config) AccountSupportRepository {
	con, err := mg.NewService(conf)
	if err != nil {
		panic(err)
	}
	// Success
	return &accountSupportRepository{con: con}
}

func (inst *accountSupportRepository) Name() (string, string) {
	// Success
	return defs.DbTIAccount, defs.ColSupport
}

func (inst *accountSupportRepository) Find(query *bson.M, sorts []string, size, offset int64) ([]*model.TTISupport, error) {
	database, collection := inst.Name()
	var results []*model.TTISupport
	if _, err := inst.con.FindMany(database, collection, query, sorts, size, offset, &results); err != nil {
		return nil, err
	}
	// Success
	return results, nil
}

func (inst *accountSupportRepository) FindAll(query *bson.M, sorts []string) ([]*model.TTISupport, error) {
	database, collection := inst.Name()
	var results []*model.TTISupport
	if _, err := inst.con.FindMany(database, collection, query, sorts, 0, 0, &results); err != nil {
		return nil, err
	}
	// Success
	return results, nil
}
