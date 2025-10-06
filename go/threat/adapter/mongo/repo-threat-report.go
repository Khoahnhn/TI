package mongo

import (
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type threatReportAlertRepository struct {
	con mg.Database
}

func (inst *threatReportAlertRepository) Name() (string, string) {
	// Success
	return defs.DbThreatReport, defs.ColReport
}

func NewThreatReportRepository(conf mg.Config) ThreatReportRepository {
	con, err := mg.NewService(conf)
	if err != nil {
		panic(err)
	}
	// Success
	return &threatReportAlertRepository{con: con}
}

func (inst *threatReportAlertRepository) Find(query *bson.M, sorts []string, size, offset int64) ([]*model.ThreatReportAlert, error) {
	database, collection := inst.Name()
	var results []*model.ThreatReportAlert
	if _, err := inst.con.FindMany(database, collection, query, sorts, size, offset, &results); err != nil {
		return nil, err
	}
	// Success
	return results, nil
}
