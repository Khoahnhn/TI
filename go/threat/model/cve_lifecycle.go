package model

import (
	"fmt"
	"time"

	"gitlab.viettelcyber.com/awesome-threat/library/hash"
)

type CVELifecycleEvent string
type CVELifecycleSource string

const (
	CVE_EVENT_APPROVE_CVE         CVELifecycleEvent = "approve_cve"
	CVE_EVENT_ANALYSIS_TIME       CVELifecycleEvent = "analysis_time"
	CVE_EVENT_INDEPTH_ANALYSIS    CVELifecycleEvent = "indepth_analysis"
	CVE_EVENT_CREATE_CVE          CVELifecycleEvent = "create_cve"
	CVE_EVENT_CVE_CISA_KEY_UPDATE CVELifecycleEvent = "cve_cisa_key_update"
	CVE_EVENT_CVE_RECEIVED        CVELifecycleEvent = "cve_received"
)

const (
	CVE_SOURCE_NVD CVELifecycleSource = "nvd"
	CVE_SOURCE_VTI CVELifecycleSource = "vti"
)

type (
	CVELifecycle struct {
		ID      string             `json:"id"`
		CVEId   string             `json:"cve_id"`
		CVECode string             `json:"cve_code"`
		Created int64              `json:"created"`
		Link    string             `json:"link"`
		Source  CVELifecycleSource `json:"source"`
		Event   CVELifecycleEvent  `json:"event"`
		Creator string             `json:"creator"`
	}
)

func (doc *CVELifecycle) GetID() string {
	// Success
	return doc.ID
}

func (doc *CVELifecycle) SetEID(id string) {
	// Success
	doc.ID = id
}

func (doc *CVELifecycle) GenerateId(value string) {
	id := hash.SHA1(fmt.Sprintf("%s_%d", value, time.Now().UnixMilli()))
	doc.ID = id
}
