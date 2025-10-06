package model

import (
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"go.mongodb.org/mongo-driver/bson"
	"regexp"
)

type (
	Role struct {
		ID                 string                     `json:"id" bson:"_id"`
		RoleID             string                     `json:"role_id" bson:"role_id"`
		Permissions        []string                   `json:"permissions" bson:"permissions"`
		Privileges         []Privilege                `json:"privileges" bson:"privileges"`
		Description        string                     `json:"description" bson:"description"`
		MultiLang          map[string]LanguageContent `json:"multi_lang,omitempty" bson:"multi_lang,omitempty"`
		Month              int                        `json:"month" bson:"month"`
		Mass               bool                       `json:"mass" bson:"mass"`
		LimitAlert         int                        `json:"limit_alert" bson:"limit_alert"`
		LimitAccount       int                        `json:"limit_account" bson:"limit_account"`
		LimitAssetAliases  int                        `json:"limit_asset_aliases" bson:"limit_asset_aliases"`
		LimitAssetIPDomain int                        `json:"limit_asset_ipdomain" bson:"limit_asset_ipdomain"`
		LimitAssetProduct  int                        `json:"limit_asset_product" bson:"limit_asset_product"`
		Level              int                        `json:"level" bson:"level"`
		PriceListID        *string                    `json:"pricelist_id" bson:"pricelist_id"` //paygate package
		PaygatePackageName *string                    `json:"paygate_package_name" bson:"paygate_package_name"`
		ReportPackage      *bool                      `json:"report_package" bson:"report_package"`
		Languages          []string                   `json:"languages" bson:"languages"`
		Creator            string                     `json:"creator" bson:"creator"`
		Editor             string                     `json:"editor" bson:"editor"`
		CreatedAt          int64                      `json:"created_at" bson:"created_at"`
		UpdatedAt          int64                      `json:"updated_at" bson:"updated_at"`
	}

	Privilege struct {
		Resource string   `json:"resource"`
		Action   []string `json:"action"`
	}

	LanguageContent struct {
		Description string `json:"description"`
	}

	RequestRoleCreate struct {
		// chung cho cả Mass và Enterprise
		RoleID      string `json:"role_id" mod:"trim" validate:"required,min=5,max=30"`
		Description string `json:"description" mod:"trim" validate:"required,min=1,max=500"`
		Type        string `json:"type" validate:"required,oneof=mass enterprise"`
		Month       int    `json:"month" validate:"gte=0,lte=1000"`
		Level       int    `json:"level" validate:"required,numeric,min=1"`
		Language    string `json:"language" mod:"lcase" validate:"required,oneof=vi en jp"`
		// -1: unlimited, >=0: limit value
		LimitAccount  int                        `json:"limit_account" validate:"gte=-1,lte=1000"`
		LimitAlert    int                        `json:"limit_alert" validate:"gte=-1,lte=1000"`
		LimitIPDomain int                        `json:"limit_ip_domain" validate:"gte=-1,lte=1000"`
		LimitProduct  int                        `json:"limit_product" validate:"gte=-1,lte=1000"`
		LimitAliases  int                        `json:"limit_aliases" validate:"gte=-1,lte=1000"`
		Privileges    map[string]map[string]bool `json:"privileges" bson:"privileges"`
		// Chỉ có ở Mass (không có ở Enterprise)
		ReportPackage      *bool   `json:"report_package,omitempty"`
		PaygatePackage     *string `json:"paygate_package,omitempty"`
		PaygatePackageName *string `json:"paygate_package_name,omitempty"`
	}

	RequestRoleEdit struct {
		ID string `param:"id" validate:"required"` //roleId
		// chung cho cả Mass và Enterprise
		Description string `json:"description" mod:"trim" validate:"required,min=1,max=500"`
		Type        string `json:"type" validate:"required,oneof=mass enterprise"`
		Month       int    `json:"month" validate:"gte=0,lte=1000"`
		Level       int    `json:"level" validate:"required,numeric,min=1"`
		Language    string `json:"language" mod:"lcase" validate:"required,oneof=vi en jp"`
		// -1: unlimited, >=0: limit value
		LimitAccount  int                        `json:"limit_account" validate:"gte=-1,lte=1000"`
		LimitAlert    int                        `json:"limit_alert" validate:"gte=-1,lte=1000"`
		LimitIPDomain int                        `json:"limit_ip_domain" validate:"gte=-1,lte=1000"`
		LimitProduct  int                        `json:"limit_product" validate:"gte=-1,lte=1000"`
		LimitAliases  int                        `json:"limit_aliases" validate:"gte=-1,lte=1000"`
		Privileges    map[string]map[string]bool `json:"privileges" bson:"privileges"`
		// Chỉ có ở Mass (không có ở Enterprise)
		ReportPackage      *bool   `json:"report_package,omitempty"`
		PaygatePackage     *string `json:"paygate_package,omitempty"`
		PaygatePackageName *string `json:"paygate_package_name,omitempty"`
	}

	RequestRoleID struct {
		ID string `param:"id" mod:"trim" validate:"required"` //roleId
	}

	RequestRoleStatistic struct {
		PaygatePackage []string `json:"paygate_package" mod:"trim"`
		Level          []int    `json:"level" validate:"omitempty,dive,min=1"`
		Features       []string `json:"features" mod:"trim"`
		Keyword        string   `json:"keyword" mod:"trim"`
	}

	RequestRoleSearch struct {
		RequestRoleStatistic
		ReportPackage []string `json:"report_package" mod:"trim,lcase" validate:"omitempty,max=2,dive,oneof=true false"`
		Type          []string `json:"type" mod:"trim,lcase" validate:"dive,oneof=mass enterprise"`
		IsNotReport   *bool    `json:"is_not_report"`
		Sort          []string `json:"sort"`
		Size          int64    `json:"size" validate:"numeric,gte=0"`
		Offset        int64    `json:"offset" validate:"numeric,gte=0"`
	}

	RoleResponse struct {
		Role
		Privileges map[string]map[string]bool `json:"privileges"`
	}
)

func (doc *Role) GetID() any {
	return doc.ID
}

func (body *RequestRoleCreate) Generate(creator string, now int64) *Role {
	role := &Role{
		ID:                 hash.SHA1(body.RoleID),
		RoleID:             body.RoleID,
		Mass:               body.Type == defs.PackageTypeMass,
		Description:        body.Description,
		Month:              body.Month,
		Level:              body.Level,
		Creator:            creator,
		Languages:          []string{body.Language},
		MultiLang:          map[string]LanguageContent{},
		LimitAccount:       body.LimitAccount,
		LimitAlert:         body.LimitAlert,
		LimitAssetIPDomain: body.LimitIPDomain,
		LimitAssetProduct:  body.LimitProduct,
		LimitAssetAliases:  body.LimitAliases,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	switch body.Language {
	case "vi":
		role.MultiLang[body.Language] = LanguageContent{Description: body.Description}
	case "en":
		role.MultiLang[body.Language] = LanguageContent{Description: body.Description}
	case "jp":
		role.MultiLang[body.Language] = LanguageContent{Description: body.Description}
	}
	if body.Type == defs.PackageTypeMass {
		role.ReportPackage = body.ReportPackage
		role.PriceListID = body.PaygatePackage
		role.PaygatePackageName = body.PaygatePackageName
	}
	return role
}

func (body *RequestRoleSearch) Query() *bson.M {
	filter := bson.M{}
	if body.Keyword != "" {
		regexSearch := regexp.QuoteMeta(body.Keyword)
		filter["$or"] = bson.A{
			bson.M{"multi_lang.vi.description": bson.M{"$regex": regexSearch, "$options": "i"}},
			bson.M{"multi_lang.en.description": bson.M{"$regex": regexSearch, "$options": "i"}},
			bson.M{"multi_lang.jp.description": bson.M{"$regex": regexSearch, "$options": "i"}},
			bson.M{"role_id": bson.M{"$regex": regexSearch, "$options": "i"}},
		}
	}
	if len(body.Features) > 0 {
		filter["privileges.resource"] = bson.M{"$in": body.Features}
	}
	if len(body.PaygatePackage) > 0 {
		filter["paygate_package_name"] = bson.M{"$in": body.PaygatePackage}
	}
	if len(body.Type) > 0 {
		var massValues []bool
		for _, t := range body.Type {
			switch t {
			case "mass":
				massValues = append(massValues, true)
			case "enterprise":
				massValues = append(massValues, false)
			}
		}
		if len(massValues) > 0 {
			filter["mass"] = bson.M{"$in": massValues}
		}
	}
	if len(body.ReportPackage) > 0 || body.IsNotReport != nil {
		if len(body.ReportPackage) > 0 {
			var reportPackageValues []bool
			for _, report := range body.ReportPackage {
				switch report {
				case "true":
					reportPackageValues = append(reportPackageValues, true)
				case "false":
					reportPackageValues = append(reportPackageValues, false)
				}
			}

			if len(reportPackageValues) > 0 {
				filter["report_package"] = bson.M{"$in": reportPackageValues}
			}
		}
		if body.IsNotReport != nil {
			if *body.IsNotReport {
				filter["report_package"] = bson.M{
					"$ne":     true,
					"$exists": true,
				}
			} else {
				filter["report_package"] = true
			}
		}
	}
	if len(body.Level) > 0 {
		filter["level"] = bson.M{"$in": body.Level}
	}
	if len(filter) == 0 {
		return &bson.M{}
	}
	// Success
	return &filter
}
