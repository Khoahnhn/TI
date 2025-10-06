package mongo

import (
	"context"
	"log"

	libmongo "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type groupUserRepositoryV2 struct {
	client *mongo.Client
}

func NewGroupUserRepositoryV2(conf libmongo.Config) GroupUserRepositoryV2 {
	clientOpts := []*options.ClientOptions{
		options.Client().ApplyURI(conf.String()),
	}
	if conf.Auth.Enable {
		clientOpts = append(clientOpts, options.Client().SetAuth(options.Credential{
			AuthSource: conf.Auth.AuthDB,
			Username: conf.Auth.Username,
			Password: conf.Auth.Password,
		}))
	}
	client, err := mongo.Connect(context.TODO(), clientOpts...)
	if err != nil {
		log.Fatal(err)
	}
	return &groupUserRepositoryV2{
		client: client,
	}
}

func (r *groupUserRepositoryV2) Name() (string, string) {
	return defs.DatabaseTIAccount, defs.CollectionGroupUser
}

func (r *groupUserRepositoryV2) BulkUpdateById(ctx context.Context, orgs []*model.Organization) error {
	bulkModels := []mongo.WriteModel{}
	for _, org := range orgs {
		bulkModels = append(bulkModels, mongo.
			NewUpdateOneModel().
			SetFilter(bson.M{"_id": org.Id}).
			SetUpdate(bson.M{"$set": org}))
	}
	opts := options.BulkWrite().SetOrdered(false)
	database, collectionName := r.Name()
	collection := r.client.Database(database).Collection(collectionName)
	_, err := collection.BulkWrite(ctx, bulkModels, opts)
	if err != nil {
		return err
	}
	return nil
}
