package model

import "gitlab.viettelcyber.com/awesome-threat/library/clock"

type (
	GroupUser struct {
		TenantID    string `bson:"tenant_id" json:"tenant_id"`
		Active      bool   `json:"active" bson:"active"`
		ExpiredTime int64  `json:"expired_time" bson:"expired_time"`
		Name        string `bson:"name" json:"name"`
		Role        string `bson:"role" json:"role"`
	}

	GroupUsers []*GroupUser
)

func (doc *GroupUser) GetID() string {
	// Success
	return doc.TenantID
}

func (doc *GroupUser) IsActive() bool {
	if !doc.Active {
		return false
	}
	if doc.ExpiredTime == 0 {
		return true
	}
	now, _ := clock.Now(clock.Local)
	// Success
	return clock.Unix(now) < doc.ExpiredTime
}

func (doc GroupUsers) Len() int {
	// Success
	return len(doc)
}

func (doc GroupUsers) Less(i, j int) bool {
	// Success
	return doc[i].TenantID < doc[j].TenantID
}

func (doc GroupUsers) Swap(i, j int) {
	// Success
	doc[i], doc[j] = doc[j], doc[i]
}
