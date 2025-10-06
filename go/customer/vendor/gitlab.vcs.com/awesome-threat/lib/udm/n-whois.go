package udm

import (
	"fmt"
	"time"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
)

type Whois struct {
	Name                string                 `json:"name,omitempty"`
	NameServer          []string               `json:"name_server,omitempty"`
	Status              string                 `json:"status,omitempty"`
	IANARegistrarID     int                    `json:"iana_registrar_id,omitempty"`
	PrivateRegistration *bool                  `json:"private_registration,omitempty"`
	CreationTime        int64                  `json:"creation_time,omitempty"`
	ExpirationTime      int64                  `json:"expiration_time,omitempty"`
	FirstSeenTime       int64                  `json:"first_seen_time,omitempty"`
	AuditUpdateTime     int64                  `json:"audit_update_time,omitempty"`
	UpdateTime          int64                  `json:"update_time,omitempty"`
	WhoisTime           int64                  `json:"whois_time,omitempty"`
	WhoisServer         string                 `json:"whois_server,omitempty"`
	WhoisRecordRawText  string                 `json:"whois_record_raw_text,omitempty"`
	RegistryDataRawText string                 `json:"registry_data_raw_text,omitempty"`
	Registrar           *User                  `json:"registrar,omitempty"`
	Admin               *User                  `json:"admin,omitempty"`
	Billing             *User                  `json:"billing,omitempty"`
	Registrant          *User                  `json:"registrant,omitempty"`
	Tech                *User                  `json:"tech,omitempty"`
	Zone                *User                  `json:"zone,omitempty"`
	Flat                map[string]interface{} `json:"flat,omitempty"`
}

func (inst *Whois) Flatten() map[string]interface{} {
	flattened := make(map[string]interface{})
	flattened["Domain Name"] = inst.Name

	if len(inst.NameServer) > 0 {
		flattened["Name Servers"] = inst.NameServer
	}

	if inst.Status != "" {
		flattened["Domain Status"] = inst.Status
	}

	if inst.IANARegistrarID != 0 {
		flattened["Registrar IANA ID"] = inst.IANARegistrarID
	}

	if inst.CreationTime > 0 {
		flattened["Creation Date"] = clock.Format(time.UnixMilli(inst.CreationTime), clock.FormatRFC3339CZ)
	}
	if inst.ExpirationTime > 0 {
		flattened["Expiration Date"] = clock.Format(time.UnixMilli(inst.ExpirationTime), clock.FormatRFC3339CZ)
	}
	if inst.UpdateTime > 0 {
		flattened["Updated Date"] = clock.Format(time.UnixMilli(inst.UpdateTime), clock.FormatRFC3339CZ)
	}

	if inst.Registrar != nil {
		flattenedRegistrar := inst.Registrar.Flatten()
		for k, v := range flattenedRegistrar {
			flattened[fmt.Sprintf("%s %s", "Registrar", k)] = v
		}
	}

	if inst.Admin != nil {
		flattenedAdmin := inst.Admin.Flatten()
		for k, v := range flattenedAdmin {
			flattened[fmt.Sprintf("%s %s", "Admin", k)] = v
		}
	}

	if inst.Billing != nil {
		flattenedBilling := inst.Billing.Flatten()
		for k, v := range flattenedBilling {
			flattened[fmt.Sprintf("%s %s", "Billing", k)] = v
		}
	}

	if inst.Registrant != nil {
		flattenedRegistrant := inst.Registrant.Flatten()
		for k, v := range flattenedRegistrant {
			flattened[fmt.Sprintf("%s %s", "Registrant", k)] = v
		}
	}

	if inst.Tech != nil {
		flattenedTech := inst.Tech.Flatten()
		for k, v := range flattenedTech {
			flattened[fmt.Sprintf("%s %s", "Tech", k)] = v
		}
	}

	if inst.Zone != nil {
		flattenedZone := inst.Zone.Flatten()
		for k, v := range flattenedZone {
			flattened[fmt.Sprintf("%s %s", "Zone", k)] = v
		}
	}
	// Success
	return flattened
}
