package mongo

import (
	"context"
	"fmt"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
)

type userHistoryRepository struct {
	con      mongo.Database
	database string
}

func (u userHistoryRepository) FindAll(ctx context.Context, pipeline []*bson.M) ([]*model.UserHistory, int64, error) {
	//TODO implement me
	database, collection := u.Name()

	var results []struct {
		Data  []*model.UserHistory `bson:"data"`
		Total []struct {
			Count int64 `bson:"count"`
		} `bson:"total"`
	}
	err := u.con.Aggregate(database, collection, pipeline, &results)
	if err != nil {
		return nil, 0, err
	}

	if len(results) == 0 {
		return []*model.UserHistory{}, 0, nil
	}
	users := results[0].Data
	total := int64(0)
	if len(results[0].Total) > 0 {
		total = results[0].Total[0].Count
	}

	return users, total, nil
}

func (u userHistoryRepository) Create(ctx context.Context, userHistory *model.UserHistory) error {
	//TODO implement me
	database, collection := u.Name()
	if userHistory == nil {
		return fmt.Errorf("userHistory is nil")
	}

	userHistory.GenID()
	userHistory.SetTimestamps()

	return u.con.InsertOne(database, collection, userHistory)
}

func (u userHistoryRepository) Name() (string, string) {
	//TODO implement me
	return u.database, defs.CollectionUserHistory
}

func NewUserHistoryRepository(conf mongo.Config, database string) UserHistoryRepository {
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}
	if database == "" {
		database = defs.DatabaseTIAccount
	}
	if err = con.CreateIndex(defs.DatabaseTIAccount, defs.CollectionUserHistory, &bson.M{
		"user_id": -1,
	}, false); err != nil {
		panic(err)
	}
	return &userHistoryRepository{con: con, database: database}
}
