package mongo

import (
	"context"
	"errors"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	mongodriver "go.mongodb.org/mongo-driver/mongo"
)

type userV3Repository struct {
	con      mongo.Database
	database string
}

func (u userV3Repository) CountByGroupID(ctx context.Context, groupID string) (int64, error) {
	//TODO implement me
	database, collection := u.Name()
	query := bson.M{"group_id": groupID}
	total, err := u.con.Count(database, collection, &query)
	if err != nil {
		return 0, err
	}
	return total, err
}

func (u userV3Repository) Update(ctx context.Context, id primitive.ObjectID, data bson.M) error {
	database, collection := u.Name()
	// Chỉ update các field cần thiết, không phải toàn bộ object
	update := bson.M{
		"$set": data,
	}

	return u.con.UpdateByID(database, collection, id, update)
}

func (u userV3Repository) FindByID(ctx context.Context, id primitive.ObjectID) (*model.UserV3, error) {
	//TODO implement me
	database, collection := u.Name()

	query := bson.M{"_id": id}
	result := new(model.UserV3)
	err := u.con.FindOne(database, collection, &query, nil, 0, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (u userV3Repository) DeleteByID(ctx context.Context, id primitive.ObjectID) error {
	//TODO implement me
	database, collection := u.Name()
	err := u.con.DeleteByID(database, collection, id)
	if err != nil {
		return err
	}
	return nil
}

func (u userV3Repository) Create(ctx context.Context, user *model.UserV3) error {
	//TODO implement me
	database, collection := u.Name()
	if user == nil {
		return errors.New("user is nil")
	}
	user.GenID()
	return u.con.InsertOne(database, collection, user)
}

func (u userV3Repository) FindByUserName(ctx context.Context, username string) (*model.UserV3, error) {
	database, collection := u.Name()

	query := bson.M{"username": username}
	result := new(model.UserV3)

	err := u.con.FindOne(database, collection, &query, nil, 0, result)
	if err != nil {
		// Trường hợp not found thì không coi là lỗi
		if errors.Is(err, mongodriver.ErrNoDocuments) || err.Error() == "not found" {
			return nil, nil
		}
		return nil, err
	}

	return result, nil
}

func (u userV3Repository) Detail(ctx context.Context, pipeline []*bson.M) (*model.UserV3Aggregate, error) {
	//TODO implement me
	database, collection := u.Name()

	// decode kết quả facet
	var results []*model.UserV3Aggregate
	err := u.con.Aggregate(database, collection, pipeline, &results)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, nil
	}

	return results[0], nil
}

func (u userV3Repository) StatisticV3(ctx context.Context, pipeline []*bson.M) (*model.SearchUserV3Statistic, error) {
	database, collection := u.Name()

	// $facet luôn trả về 1 array với 1 phần tử
	var facetResults []model.FacetResult
	err := u.con.Aggregate(database, collection, pipeline, &facetResults)
	if err != nil {
		return nil, err
	}
	if len(facetResults) == 0 {
		return &model.SearchUserV3Statistic{}, nil
	}

	facet := facetResults[0]

	// Chuyển Country và Package từ struct trung gian sang []string
	var countries []string
	if len(facet.Country) > 0 {
		countries = facet.Country[0].Values
	}

	var packages []string
	if len(facet.Package) > 0 {
		packages = facet.Package[0].Values
	}

	// Build kết quả cuối cùng trả ra API
	result := &model.SearchUserV3Statistic{
		Active:    facet.Status,    // map sang active
		Ownership: facet.Ownership, // map sang ownership
		Mass:      facet.Type,      // map sang mass
		Country:   countries,
		Package:   packages,
	}

	return result, nil
}

func (u userV3Repository) Name() (string, string) {
	//TODO implement me
	return u.database, defs.CollectionUser
}

func (u userV3Repository) FindUserV3(ctx context.Context, pipeline []*bson.M) ([]*model.UserV3Aggregate, int64, error) {
	//TODO implement me
	database, collection := u.Name()

	// decode kết quả facet
	var results []struct {
		Data  []*model.UserV3Aggregate `bson:"data"`
		Total []struct {
			Count int64 `bson:"count"`
		} `bson:"total"`
	}

	err := u.con.Aggregate(database, collection, pipeline, &results)
	if err != nil {
		return nil, 0, err
	}

	if len(results) == 0 {
		return []*model.UserV3Aggregate{}, 0, nil
	}

	users := results[0].Data
	total := 0
	if len(results[0].Total) > 0 {
		total = int(results[0].Total[0].Count)
	}

	return users, int64(total), nil
}

func NewUserV3Repository(conf mongo.Config, database string) UserV3Repository {
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}

	if database == "" {
		database = defs.DatabaseTIAccount
	}
	return &userV3Repository{con: con, database: database}
}
