package mongo

import (
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
	"go.mongodb.org/mongo-driver/bson"
)

type rolesRepository struct {
	con mongo.Database
}

func NewRoleRepository(conf mongo.Config) AccountRolesRepository {
	// Success
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}
	return &rolesRepository{con: con}
}

func (inst *rolesRepository) Name() (string, string) {
	// Success
	return defs.DbTIAccount, defs.ColRoles
}

func (inst *rolesRepository) FindAll(query *bson.M, sorts []string) ([]*model.Role, error) {
	database, collection := inst.Name()
	var results []*model.Role
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
