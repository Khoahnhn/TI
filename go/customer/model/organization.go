package model

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type (
	Organization struct {
		Id               string                `json:"_id" bson:"_id"`
		TenantId         string                `json:"tenant_id" bson:"tenant_id" validate:"required,min=5,max=30,code"`
		Name             string                `json:"name" bson:"name" validate:"required"`
		Description      string                `json:"description" bson:"description"`
		CreatedTime      int64                 `json:"created_time" bson:"created_time"`
		UpdatedTime      int64                 `json:"updated_time" bson:"updated_time"`
		Active           bool                  `json:"active" bson:"active"`
		Parent           string                `json:"parent" bson:"parent"`
		ParentName       string                `json:"parent_name" bson:"parent_name"`
		ParentId         string                `json:"parent_id" bson:"parent_id" validate:"required"`
		Ancestors        []string              `json:"ancestor" bson:"ancestors"`
		Industry         []string              `json:"industry" bson:"industry" validate:"required"`
		Role             string                `json:"role" bson:"role" validate:"required"`
		EffectiveTime    int64                 `json:"effective_time" bson:"effective_time" validate:"required"`
		ExpiredTime      int64                 `json:"expired_time" bson:"expired_time" validate:"required"`
		MassAlertQuota   int                   `json:"mass_alert_quota" bson:"mass_alert_quota"`
		MassNextSyncTime int                   `json:"mass_next_sync_time" bson:"mass_next_sync_time"`
		CompanySize      int                   `json:"company_size" bson:"company_size"`
		Lang             []defs.Language       `json:"lang" bson:"lang"`
		Multilang        OrganizationMultilang `json:"multilang" bson:"multilang"`
	}

	OrganizationMultilang struct {
		Vi *OrganizationInfo `json:"vi" bson:"vi" validate:"required"`
		En *OrganizationInfo `json:"en" bson:"en,omitempty"`
		Jp *OrganizationInfo `json:"jp" bson:"jp,omitempty"`
	}

	OrganizationInfo struct {
		Name string `json:"name" bson:"name"`
	}

	OrganizationHistory struct {
		Id          primitive.ObjectID   `json:"_id" bson:"_id,omitempty"`
		OrgId       string               `json:"-" bson:"org_id"`
		Creator     string               `json:"creator" bson:"creator"`
		Event       defs.OrgHistoryEvent `json:"event" bson:"event"`
		CreatedTime int64                `json:"created_time" bson:"created_time"`
		Actions     []string             `json:"actions,omitempty" bson:"action,omitempty"`
		OrgBefore   string               `json:"org_before,omitempty" bson:"org_before,omitempty"`
		OrgAfter    string               `json:"org_after,omitempty" bson:"org_after,omitempty"`
	}

	OrganizationSearchData struct {
		Organization `bson:",inline"`
		Package      Role `json:"package" bson:"package"`
	}

	OrganizationSearchMongoAgg struct {
		Total int                      `json:"totalCount" bson:"totalCount"`
		Data  []OrganizationSearchData `json:"data" bson:"data"`
	}

	OrganizationStats struct {
		Total       int      `json:"total" bson:"total"`
		ActiveCount int      `json:"active_count" bson:"active_count"`
		MassCount   int      `json:"mass_count" bson:"mass_count"`
		Industries  []string `json:"industries" bson:"industries"`
		Packages    []string `json:"packages" bson:"packages"`
	}

	RequestSearchOrganization struct {
		EffectiveInterval RequestTimeInterval `json:"effective_interval"`
		ExpiredInterval   RequestTimeInterval `json:"expired_interval"`
		SearchTerm        string              `json:"search"`
		Package           []string            `json:"package"`
		IndustrySector    []string            `json:"industry_sector"`
		StatusActive      []bool              `json:"status"`
		TypeIsMass        []bool              `json:"type_is_mass"`
	}

	RequestStoreOrganization struct {
		TenantId      string        `json:"tenant_id" validate:"required,min=5,max=30,code"`
		Description   string        `json:"description"`
		Active        bool          `json:"status"`
		ParentId      string        `json:"parent_id" validate:"required"`
		Industry      []string      `json:"industry" validate:"required"`
		PackageId     string        `json:"package_id" validate:"required"`
		EffectiveTime int64         `json:"effective_time"`
		ExpiredTime   int64         `json:"expired_time"`
		CompanySize   int           `json:"company_size"`
		Name          string        `json:"name"`
		Lang          defs.Language `json:"lang"`
		Parent        *Organization `json:"-"`
		Role          *Role         `json:"-"`
	}

	RequestOrganizationHistories struct {
		Time  RequestTimeInterval  `json:"time"`
		Event defs.OrgHistoryEvent `json:"event"`
	}

	RequestOrganizationChangeStatus struct {
		Ids        []string `json:"ids" validate:"required"`
		Active     bool     `json:"active"`
		UpdateTime bool     `json:"update_time"`
	}

	ResponseOrganization struct {
		Organization
		PackageName    string `json:"package_name"`
		PackageMass    bool   `json:"package_mass"`
		MassAlertLimit int    `json:"mass_alert_limit"`
	}

	ResponseOrganizationStatistic struct {
		Status       []AggBoolFieldValuev3 `json:"status"`
		PackageType  []AggBoolFieldValuev3 `json:"package_type"`
		PackageNames []string              `json:"package_name"`
		Industries   []IndustrySector      `json:"industries"`
	}

	ResponseSearchOrganization struct {
		Total int                    `json:"total"`
		Data  []ResponseOrganization `json:"data"`
	}

	RequestOrganizationID struct {
		Organization string `json:"organization" query:"organization"`
	}

	RequestOrganizationGetUser struct {
		ID       string `json:"id" param:"id" validate:"required"`
		Username string `json:"username" param:"username" validate:"required"`
	}

	IndustrySector struct {
		Value string `json:"value"`
		Desc  string `json:"desc"`
	}
)

func (body *RequestOrganizationID) Query(field string) (map[string]interface{}, bool) {
	if body.Organization == "" {
		return nil, false
	}
	// Success
	return map[string]interface{}{"term": map[string]interface{}{field: body.Organization}}, true
}

func (o *Organization) GetID() any {
	return o.Id
}

func (o *Organization) GenID() {
	h := sha1.New()
	h.Write([]byte(strings.ToLower(o.TenantId)))
	hashBytes := h.Sum(nil)
	hashHex := hex.EncodeToString(hashBytes)
	o.Id = hashHex
}

func (o *OrganizationHistory) GetID() any {
	return o.Id
}
