package mongo

import "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"

type settingsRepository struct {
	schedule ScheduleRepository
}

func (inst *settingsRepository) Schedule() ScheduleRepository {
	// Success
	return inst.schedule
}

func NewSettingsRepository(conf mongo.Config, database string) SettingsRepository {
	return &settingsRepository{schedule: NewScheduleRepository(conf, database)}
}
