package model

type ThreatReportAlert struct {
	ApprovedTime int64                  `bson:"approved_time"`
	CodeReport   string                 `bson:"code_report"`
	Multilang    map[string]interface{} `bson:"multilang"`
}
