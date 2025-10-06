package mongo

import (
	"context"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"

	"go.mongodb.org/mongo-driver/bson"
)

type scheduleRepository struct {
	con      mongo.Database
	database string
}

func (s scheduleRepository) GetSchedules(ctx context.Context, groupID string) ([]model.Schedule, error) {
	//TODO implement me
	database, collection := s.Name()
	var schedules []model.Schedule

	query := bson.M{"extra_data.group_id": groupID}
	_, err := s.con.FindMany(
		database,
		collection,
		&query,
		nil,
		0,
		0,
		&schedules,
	)
	if err != nil {
		return nil, err
	}

	return schedules, nil
}

func (s scheduleRepository) Name() (string, string) {
	//TODO implement me
	return defs.DatabaseSettings, defs.CollectionsSchedule
}

func NewScheduleRepository(conf mongo.Config, database string) ScheduleRepository {
	con, err := mongo.NewService(conf)
	if err != nil {
		panic(err)
	}
	if database == "" {
		database = defs.DatabaseSettings
	}
	// Success
	return &scheduleRepository{
		con:      con,
		database: database,
	}
}
