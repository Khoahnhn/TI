package model

type (
	GroupUser struct {
		ID             string   `json:"id" bson:"_id"`
		TenantID       string   `json:"tenant_id" bson:"tenant_id"`
		Ancestors      []string `json:"ancestors" bson:"ancestors"`
		Parent         string   `json:"parent" bson:"parent"`
		Name           string   `json:"name" bson:"name"`
		Industry       []string `json:"industry" bson:"industry"`
		Active         bool     `json:"active" bson:"active"`
		ExpiredTime    int64    `json:"expired_time" bson:"expired_time"`
		Role           string   `json:"role" bson:"role"`
		MassAlertQuota int      `json:"mass_alert_quota" bson:"mass_alert_quota"`
		Permissions    []string `json:"permissions" bson:"-"`
	}

	GroupUserSummary struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		Parent    string   `json:"parent"`
		Ancestors []string `json:"ancestors"`
	}
)

var (
	GroupIndustries = []*GroupUserSummary{
		{
			ID:        "global",
			Name:      "Global",
			Parent:    "root",
			Ancestors: []string{"root"},
		},
		{
			ID:        "banking",
			Name:      "Banking",
			Parent:    "root",
			Ancestors: []string{"root"},
		},
		{
			ID:        "finance",
			Name:      "Finance",
			Parent:    "root",
			Ancestors: []string{"root"},
		},
		{
			ID:        "telecom",
			Name:      "Telecom",
			Parent:    "root",
			Ancestors: []string{"root"},
		},
		{
			ID:        "government",
			Name:      "Government",
			Parent:    "root",
			Ancestors: []string{"root"},
		},
		{
			ID:        "other",
			Name:      "Other",
			Parent:    "root",
			Ancestors: []string{"root"},
		},
	}
)

func (doc *GroupUser) GetID() string {
	// Success
	return doc.ID
}

func (doc *GroupUser) Summary() *GroupUserSummary {
	// Success
	return &GroupUserSummary{
		ID:        doc.TenantID,
		Name:      doc.Name,
		Parent:    doc.Parent,
		Ancestors: doc.Ancestors,
	}
}
