package udm

import (
	"fmt"
	"math/big"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
)

type Artifact struct {
	ASOwner         string                 `json:"as_owner,omitempty"`
	ASN             int64                  `json:"asn,omitempty"`
	FirstSeenTime   int64                  `json:"first_seen_time,omitempty"`
	LastSeenTime    int64                  `json:"last_seen_time,omitempty"`
	IP              string                 `json:"ip,omitempty"`
	Location        *Location              `json:"location,omitempty"`
	Subnet          string                 `json:"subnet,omitempty"`
	SubnetMin       string                 `json:"subnet_min,omitempty"`
	SubnetMinNumber *big.Int               `json:"subnet_min_number,omitempty"`
	SubnetMax       string                 `json:"subnet_max,omitempty"`
	SubnetMaxNumber *big.Int               `json:"subnet_max_number,omitempty"`
	Flat            map[string]interface{} `json:"flat,omitempty"`
	// RFC7483
	Registrant    []*User `json:"registrant,omitempty"`
	Technical     []*User `json:"technical,omitempty"`
	Admin         []*User `json:"admin,omitempty"`
	Abuse         []*User `json:"abuse,omitempty"`
	Billing       []*User `json:"billing,omitempty"`
	Registrar     []*User `json:"registrar,omitempty"`
	Reseller      []*User `json:"reseller,omitempty"`
	Sponsor       []*User `json:"sponsor,omitempty"`
	Proxy         []*User `json:"proxy,omitempty"`
	Notifications []*User `json:"notifications,omitempty"`
	NOC           []*User `json:"noc,omitempty"`
}

func (inst *Artifact) Flatten() map[string]interface{} {
	flattened := make(map[string]interface{})
	flattened["IP"] = inst.IP

	if inst.ASOwner != "" {
		flattened["ASL"] = inst.ASOwner
	}

	if inst.ASN != 0 {
		flattened["ASN"] = inst.ASN
	}

	if inst.FirstSeenTime > 0 {
		firstSeen, _ := clock.ParseMilliTimestamp(inst.FirstSeenTime, clock.Local)
		flattened["First Seen"] = clock.Format(firstSeen, clock.FormatRFC3339CZ)
	}

	if inst.LastSeenTime > 0 {
		lastSeen, _ := clock.ParseMilliTimestamp(inst.LastSeenTime, clock.Local)
		flattened["Last Seen"] = clock.Format(lastSeen, clock.FormatRFC3339CZ)
	}

	if inst.Location != nil {
		for k, v := range inst.Location.Flatten() {
			flattened[k] = v
		}
	}

	if inst.Subnet != "" {
		flattened["Subnet"] = inst.Subnet
	}

	if inst.SubnetMin != "" && inst.SubnetMax != "" {
		flattened["Subnet Range"] = fmt.Sprintf("%s - %s", inst.SubnetMin, inst.SubnetMax)
	}

	contacts := map[string][]*User{
		"Registrant":    inst.Registrant,
		"Technical":     inst.Technical,
		"Admin":         inst.Admin,
		"Abuse":         inst.Abuse,
		"Billing":       inst.Billing,
		"Registrar":     inst.Registrar,
		"Reseller":      inst.Reseller,
		"Sponsor":       inst.Sponsor,
		"Proxy":         inst.Proxy,
		"Notifications": inst.Notifications,
		"NOC":           inst.NOC,
	}

	for contactType, users := range contacts {
		for i, u := range users {
			flat := u.Flatten()
			for k, v := range flat {
				if len(users) > 1 {
					flattened[fmt.Sprintf("%s %d %s", contactType, i+1, k)] = v
				} else {
					flattened[fmt.Sprintf("%s %s", contactType, k)] = v
				}
			}
		}
	}

	// Success
	return flattened
}
