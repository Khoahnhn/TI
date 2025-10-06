package mongo

import (
	"context"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type organizationHistoryRepo struct {
	con mongo.Database
}

func NewOrgHistoryRepo(conf mongo.Config) OrganizationHistoryRepo {
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}
	if err = con.CreateIndex(defs.DatabaseTIAccount, defs.CollectionOrgHistory, &bson.M{
		"org_id": -1,
	}, false); err != nil {
		panic(err)
	}
	return &organizationHistoryRepo{con: con}
}

func (r *organizationHistoryRepo) Name() (string, string) {
	return defs.DatabaseTIAccount, defs.CollectionOrgHistory
}

func (r *organizationHistoryRepo) Insert(ctx context.Context, org *model.OrganizationHistory) error {
	database, collection := r.Name()
	return r.con.InsertOne(database, collection, org)
}

func (r *organizationHistoryRepo) InsertMany(ctx context.Context, orgs []*model.OrganizationHistory) error {
	database, collection := r.Name()
	docs := make([]mongo.Document, len(orgs))
	for i, org := range orgs {
		docs[i] = org
	}
	return r.con.InsertMany(database, collection, docs, false)
}

func (r *organizationHistoryRepo) Find(ctx context.Context, query *bson.M, sorts []string) ([]*model.OrganizationHistory, error) {
	database, collection := r.Name()
	results := make([]*model.OrganizationHistory, 0)
	_, err := r.con.FindMany(
		database,
		collection,
		query,
		sorts,
		0,
		0,
		&results)
	if err != nil {
		return nil, err
	}
	// Success
	return results, nil
}

func (r *organizationHistoryRepo) Get(ctx context.Context, id string) (*model.OrganizationHistory, error) {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"_id": objectID}

	doc, err := r.Find(ctx, &filter, []string{})
	if err != nil {
		return nil, err
	}
	if len(doc) == 0 {
		return nil, nil
	}

	return doc[0], nil
}
