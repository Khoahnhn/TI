package mongo

import (
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type accountGroupUserRepository struct {
	con mg.Database
}

func NewAccountGroupUserRepository(conf mg.Config) AccountGroupUserRepository {
	con, err := mg.NewService(conf)
	if err != nil {
		panic(err)
	}
	// Success
	return &accountGroupUserRepository{con: con}
}

func (inst *accountGroupUserRepository) Name() (string, string) {
	// Success
	return defs.DbTIAccount, defs.ColGroupUser
}

func (inst *accountGroupUserRepository) FindOne(query *bson.M, sorts []string, offset int64) (*model.GroupUser, error) {
	database, collection := inst.Name()
	var result model.GroupUser
	if err := inst.con.FindOne(database, collection, query, sorts, offset, &result); err != nil {
		return nil, err
	}
	// Success
	return &result, nil
}

func (inst *accountGroupUserRepository) FindByID(id string) (*model.GroupUser, error) {
	query := &bson.M{"_id": id}
	// Success
	return inst.FindOne(query, []string{}, 0)
}

func (inst *accountGroupUserRepository) FindByTenantID(id string) (*model.GroupUser, error) {
	query := &bson.M{"tenant_id": id}
	// Success
	return inst.FindOne(query, []string{}, 0)
}

func (inst *accountGroupUserRepository) FindAll(query *bson.M, sorts []string) ([]*model.GroupUser, error) {
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
