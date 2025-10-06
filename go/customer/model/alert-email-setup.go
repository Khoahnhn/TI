package model

import "time"

type UserSetting struct {
	ID         any      `bson:"_id" json:"id"`
	Username   string   `bson:"username" json:"username"`
	Name       string   `bson:"name" json:"name"`
	Permission string   `bson:"permission" json:"permission"`
	Actions    []Action `bson:"actions" json:"actions"`
}

type Action struct {
	ID     int  `bson:"id" json:"id"`
	Status bool `bson:"status" json:"status"`
}

type Schedule struct {
	ID          any          `bson:"_id" json:"id"`
	ExtraData   ExtraData    `bson:"extra_data" json:"extra_data"`
	Type        string       `bson:"type" json:"type"`
	Data        ScheduleData `bson:"data" json:"data"`
	TimeExecute time.Time    `bson:"time_execute" json:"time_execute"`
	Status      string       `bson:"status" json:"status"`
	TimeUpdated time.Time    `bson:"time_updated" json:"time_updated"`
}

type ExtraData struct {
	Source  string `bson:"source" json:"source"`
	Key     string `bson:"key" json:"key"`
	GroupID string `bson:"group_id" json:"group_id"`
}

type ScheduleData struct {
	Timedelta      int             `bson:"timedelta,omitempty" json:"timedelta,omitempty"`
	TimeMoment     string          `bson:"time_moment,omitempty" json:"time_moment,omitempty"`
	DayOfWeek      int             `bson:"day_of_week,omitempty" json:"day_of_week,omitempty"`
	DayInWeek      int             `bson:"day_in_week,omitempty"`
	ByDay          *ByDay          `bson:"by_day,omitempty" json:"by_day,omitempty"`
	ByNMonthAndDay *ByNMonthAndDay `bson:"by_n_month_and_day,omitempty" json:"by_n_month_and_day,omitempty"`
	ByWeekDay      *ScheduleData   `bson:"by_weekday,omitempty"`
	ByNMonthIndex  *ScheduleData   `bson:"by_n_month_index,omitempty"`
	Index          int             `bson:"index,omitempty"`
	NWeek          int             `bson:"n_week,omitempty"`
	NMonth         int             `bson:"n_month,omitempty"`
}

type ByDay struct {
	DayInMonth int    `bson:"day_in_month" json:"day_in_month"`
	TimeMoment string `bson:"time_moment" json:"time_moment"`
}

type ByNMonthAndDay struct {
	Day        int    `bson:"day" json:"day"`
	NMonth     int    `bson:"n_month" json:"n_month"`
	TimeMoment string `bson:"time_moment" json:"time_moment"`
}

type AlertConfig struct {
	Vulnerabilities AlertSetting  `json:"vulnerabilities"`
	BrandAbuse      AlertSetting  `json:"brand_abuse"`
	DataLeak        AlertSetting  `json:"data_leak"`
	Compromise      AlertSetting  `json:"compromise"`
	Malware         AlertSetting  `json:"malware"`
	Report          ReportSetting `json:"report"`
	EASM            AlertSetting  `json:"easm"`
}

type AlertSetting struct {
	Enabled   bool     `json:"enabled"`
	Frequency string   `json:"frequency"`
	LastScan  string   `json:"last_scan"`
	NextScan  string   `json:"next_scan"`
	Severity  []string `json:"severity,omitempty"`
}

type ReportSetting struct {
	Enabled   bool   `json:"enabled"`
	Daily     string `json:"daily"`
	Weekly    string `json:"weekly"`
	Monthly   string `json:"monthly"`
	Quarterly string `json:"quarterly"`
}
