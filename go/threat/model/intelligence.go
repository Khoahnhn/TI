package model

import (
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
)

type (
	Intelligence struct {
		IntelID      string      `json:"intel_id"`
		CreationDate string      `json:"creation_date"`
		UpdatedDate  string      `json:"updated_date"`
		Lang         string      `json:"lang"`
		InfoGeneral  InfoGeneral `json:"info_general"`
	}

	Delivery struct {
		IntelID      string     `json:"intel_id"`
		CreationDate string     `json:"creation_date"`
		UpdatedDate  string     `json:"updated_date"`
		Severity     int        `json:"severity"`
		Type         string     `json:"type"`
		PolicyIntel  int        `json:"policy_intel"`
		AppearInfo   AppearInfo `json:"appear_info"`
	}

	AppearInfo struct {
		AppearTime   float64 `json:"appear_time"`
		AppearLink   string  `json:"appear_link"`
		AppearStatus string
	}

	InfoGeneral struct {
		Title   string `json:"title"`
		Summary string `json:"summary"`
	}
)

func (doc *Intelligence) GetID() string {
	// Success
	return ""
}

func (doc *Intelligence) SetEID(id string) {
	// Success
}

func (doc *Delivery) GetID() string {
	// Success
	return ""
}

func (doc *Delivery) SetEID(id string) {
	// Success
}

func (doc *Delivery) Calculate() error {
	creation, err := clock.Parse(doc.CreationDate, "")
	if err != nil {
		return err
	}
	creation, _ = clock.ReplaceTimezone(creation, clock.Local)
	creationTimestamp := float64(creation.Unix()) / 3600
	appearTimestamp := doc.AppearInfo.AppearTime / 3600
	if appearTimestamp > 0 {
		delta := creationTimestamp - appearTimestamp
		switch doc.Severity {
		case defs.MappingSeverity[defs.SeverityCritical], defs.MappingSeverity[defs.SeverityHigh]:
			if delta > defs.MappingSeveritySLA[defs.PointCritical] {
				doc.AppearInfo.AppearStatus = defs.SLAFail
			} else {
				doc.AppearInfo.AppearStatus = defs.SLAPass
			}
		case defs.MappingSeverity[defs.SeverityMedium], defs.MappingSeverity[defs.SeverityLow]:
			if delta > defs.MappingSeveritySLA[defs.PointMedium] {
				doc.AppearInfo.AppearStatus = defs.SLAFail
			} else {
				doc.AppearInfo.AppearStatus = defs.SLAPass
			}
		default:
			doc.AppearInfo.AppearStatus = defs.SLANa
		}
	} else {
		doc.AppearInfo.AppearStatus = defs.SLANa
	}
	// Success
	return nil
}
