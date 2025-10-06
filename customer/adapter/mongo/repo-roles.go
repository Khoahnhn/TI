package mongo

import (
	"context"
	"errors"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"strings"
)

type rolesRepository struct {
	con      mongo.Database
	database string
}

func (r *rolesRepository) HasPermission(role *model.Role, permission string) bool {
	//TODO implement me
	if role == nil || role.Permissions == nil {
		return false
	}

	for _, perm := range role.Permissions {
		if strings.EqualFold(perm, permission) {
			return true
		}
	}

	return false
}

func NewRoleRepository(conf mongo.Config, database string) RolesRepository {
	// Success
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}
	if database == "" {
		database = defs.DatabaseTIAccount
	}
	return &rolesRepository{con: con, database: database}
}

func (inst *rolesRepository) Name() (string, string) {
	// Success
	return inst.database, defs.CollectionRoles
}

func (inst *rolesRepository) GetByName(ctx context.Context, name string) (*model.Role, error) {
	filter := bson.M{}
	filter["$or"] = bson.A{
		bson.M{"role_id": name},
		bson.M{"pricelist_id": name},
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

func (inst *rolesRepository) Find(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.Role, error) {
	if size == 0 {
		size = 10
	}
	database, collection := inst.Name()
	results := make([]*model.Role, 0)
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

func (inst *rolesRepository) FindAll(ctx context.Context, query *bson.M, sorts []string) ([]*model.Role, error) {
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

func (inst *rolesRepository) Store(ctx context.Context, document *model.Role) error {
	database, collection := inst.Name()
	if err := inst.con.InsertOne(database, collection, document); err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *rolesRepository) UpdateByID(ctx context.Context, id string, document *model.Role) error {
	database, collection := inst.Name()
	updateData := bson.M{
		"$set": bson.M{
			"editor":               document.Editor,
			"mass":                 document.Mass,
			"level":                document.Level,
			"month":                document.Month,
			"limit_alert":          document.LimitAlert,
			"limit_account":        document.LimitAccount,
			"limit_asset_ipdomain": document.LimitAssetIPDomain,
			"limit_asset_product":  document.LimitAssetProduct,
			"limit_asset_aliases":  document.LimitAssetAliases,
			"permissions":          document.Permissions,
			"report_package":       document.ReportPackage,
			"pricelist_id":         document.PriceListID,
			"paygate_package_name": document.PaygatePackageName,
			"multi_lang":           document.MultiLang,
			"privileges":           document.Privileges,
			"languages":            document.Languages,
			"updated_at":           document.UpdatedAt,
		},
	}
	err := inst.con.UpdateByID(database, collection, id, updateData)
	if err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *rolesRepository) DeleteByID(ctx context.Context, id string) error {
	database, collection := inst.Name()
	err := inst.con.DeleteByID(database, collection, id)
	if err != nil {
		return err
	}
	return nil
}

func (inst *rolesRepository) AggregationCount(ctx context.Context, query *bson.M, fields []string) (map[string][]mongo.ResultAggregationCount, error) {
	database, collection := inst.Name()
	// Success
	return inst.con.AggregationCount(database, collection, query, fields)
}

func (inst *rolesRepository) Count(ctx context.Context, query *bson.M) (int64, error) {
	database, collection := inst.Name()
	// Success
	return inst.con.Count(database, collection, query)
}
