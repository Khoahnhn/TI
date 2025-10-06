package model

import (
	"encoding/json"
	"strings"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type (
	UserV3 struct {
		ID                       primitive.ObjectID `json:"id" bson:"_id"`
		Username                 string             `json:"username" bson:"username"`
		Phone                    string             `json:"phone" bson:"phone"`
		FirstName                string             `json:"first_name" bson:"first_name"`
		LastName                 string             `json:"last_name" bson:"last_name"`
		Country                  *string            `json:"country" bson:"country"`
		Language                 string             `json:"language" bson:"language"`
		CompanyName              string             `json:"company_name" bson:"company_name"`
		CompanySize              string             `json:"company_size" bson:"company_size"`
		GroupID                  string             `json:"group_id" bson:"group_id"`
		APIKey                   string             `json:"api_key" bson:"api_key"`
		Creator                  string             `json:"creator" bson:"creator"`
		GroupRole                string             `json:"group_role" bson:"group_role"`
		LastActivity             int64              `json:"last_activity" bson:"last_activity"`
		UpdatedTime              int64              `json:"updated_time" bson:"updated_time"`
		APIKeyExpiredTime        int64              `json:"api_key_expired_time" bson:"api_key_expired_time"`
		APIKeyUpdatedTime        int64              `json:"api_key_updated_time" bson:"api_key_updated_time"`
		CreatedTime              int64              `json:"created_time" bson:"created_time"`
		Position                 *int               `json:"title_job" bson:"position"`
		Active                   bool               `json:"status" bson:"active"`
		Ownership                bool               `json:"domain_ownership" bson:"ownership"`
		TermAccept               bool               `json:"term_accept" bson:"term_accept"`
		Password                 string             `json:"-" bson:"password"`
		MfaProperties            []MfaProperty      `bson:"mfa_properties" json:"mfa_properties"`
		MfaInit                  bool               `bson:"mfa_init" json:"-"`
		ActionConfirmEmailCode   string             `json:"-" bson:"action_confirm_email_code"`
		ActionConfirmEmailTime   int64              `json:"-" bson:"action_confirm_email_time"`
		ActionConfirmEmailStatus int64              `json:"-" bson:"action_confirm_email_status"`
		Role                     string             `json:"role" bson:"role"` // reference to roles.role_id
		Ancestors                []string           `json:"ancestors" bson:"ancestors"`
	}

	UserV3Aggregate struct {
		UserV3 `bson:",inline"`
		// Flatten group info
		GroupUserEffectiveTime int64  `json:"effective_time" bson:"effective_time"`
		GroupUserExpiredTime   int64  `json:"expired_time" bson:"expired_time"`
		GroupUserName          string `json:"organization" bson:"name"`
		GroupUserTenantId      string `json:"tenant_id" bson:"tenant_id"`

		// Flatten role info
		RolePackage string `json:"package" bson:"package"`
		RoleMass    bool   `json:"type" bson:"mass"`
		MfaEnabled  bool   `bson:"mfa_enabled" json:"mfa_properties"`
	}

	MfaProperty struct {
		Enable    bool   `bson:"enable"`
		Type      string `bson:"type"`
		Timestamp int64  `bson:"timestamp"`
	}

	CreateUserPublicDTO struct {
		Username string `json:"username" validate:"required,email"`
		StoreUserPublicDTO
		CompanyName string `json:"company_name"`
		TermAccept  *bool  `json:"term_accept"`
	}

	UpdateUserPublicDTO struct {
		ID string `param:"id" validate:"required"`
		StoreUserPublicDTO
	}

	StoreUserPublicDTO struct {
		FirstName       string  `json:"first_name" validate:"required"`
		LastName        string  `json:"last_name" validate:"required"`
		Phone           string  `json:"phone" validate:"required,phone"`
		Country         *string `json:"country"`
		Language        string  `json:"language" validate:"required"`
		GroupID         string  `json:"organization" validate:"required"`
		TitleJob        *int    `json:"title_job"`
		Status          bool    `json:"status"`
		DomainOwnership bool    `json:"domain_ownership"`
		MfaEnabled      bool    `json:"two_fa,omitempty"`
	}

	NullableInt struct {
		Set   bool
		Value *int
	}

	// BaseSearchFilters - Extract common fields to reduce duplication
	BaseSearchFilters struct {
		Keyword           string   `json:"keyword,omitempty"`             // username or phone
		Package           []string `json:"package_name,omitempty"`        // select option package
		Country           []string `json:"country,omitempty"`             // select option country
		FromExpiredTime   int64    `json:"from_expired_time,omitempty"`   // filter group_user.expired_time from
		ToExpiredTime     int64    `json:"to_expired_time,omitempty"`     // filter group_user.expired_time to
		FromEffectiveTime int64    `json:"from_effective_time,omitempty"` // filter group_user.effective_time from
		ToEffectiveTime   int64    `json:"to_effective_time,omitempty"`   // filter group_user.effective_time to
	}

	SearchUserV3 struct {
		Keyword           string   `json:"keyword"`      // username or phone
		Package           []string `json:"package_name"` // select option package
		Country           []string `json:"country"`      // select option country
		Organization      []string `json:"group_id"`
		Active            []bool   `json:"status"`              // checkbox status
		Ownership         []bool   `json:"domain_ownership"`    // check box ownership
		Mass              []bool   `json:"type"`                // checkbox mass (join roles)
		FromExpiredTime   int64    `json:"from_expired_time"`   // filter group_user.expired_time from
		ToExpiredTime     int64    `json:"to_expired_time" `    // filter group_user.expired_time to
		FromEffectiveTime int64    `json:"from_effective_time"` // filter group_user.effective_time from
		ToEffectiveTime   int64    `json:"to_effective_time"`   // filter group_user.effective_time to
		Size              int64    `json:"size"`
		Offset            int64    `json:"offset"`
	}

	SearchUserV3StatisticRequest struct {
		Keyword           string   `json:"keyword,omitempty"`             // username or phone
		Package           []string `json:"package_name,omitempty"`        // select option package
		Country           []string `json:"country,omitempty"`             // select option country
		FromExpiredTime   int64    `json:"from_expired_time,omitempty"`   // filter group_user.expired_time from
		ToExpiredTime     int64    `json:"to_expired_time,omitempty"`     // filter group_user.expired_time to
		FromEffectiveTime int64    `json:"from_effective_time,omitempty"` // filter group_user.effective_time from
		ToEffectiveTime   int64    `json:"to_effective_time,omitempty"`   // filter group_user.effective_time to
		Organization      []string `json:"group_id"`
	}

	GetUserDetailV3 struct {
		ID primitive.ObjectID `json:"id" bson:"_id"`
	}

	AggBoolFieldValuev3 struct {
		Value bool  `json:"key" bson:"_id"`
		Count int64 `json:"doc_count" bson:"count"`
	}

	SearchUserV3Statistic struct {
		Active            []*AggBoolFieldValuev3 `json:"status"`
		Ownership         []*AggBoolFieldValuev3 `json:"domain_ownership"`
		Mass              []*AggBoolFieldValuev3 `json:"type"`
		Country           []string               `json:"country"`
		Package           []string               `json:"package_name"`
		Keyword           string                 `json:"keyword,omitempty"`
		FromExpiredTime   int64                  `json:"from_expired_time,omitempty"`   // filter group_user.expired_time from
		ToExpiredTime     int64                  `json:"to_expired_time,omitempty" `    // filter group_user.expired_time to
		FromEffectiveTime int64                  `json:"from_effective_time,omitempty"` // filter group_user.effective_time from
		ToEffectiveTime   int64                  `json:"to_effective_time,omitempty"`
	}

	FacetResult struct {
		Status    []*AggBoolFieldValuev3 `bson:"status"`
		Ownership []*AggBoolFieldValuev3 `bson:"ownership"`
		Type      []*AggBoolFieldValuev3 `bson:"type"`
		Country   []struct {
			Values []string `bson:"values"`
		} `bson:"country"`
		Package []struct {
			Values []string `bson:"values"`
		} `bson:"package"`
	}

	ChangeStatusUserDTO struct {
		Status   defs.UserStatus `json:"active"`
		UpdateBy string          `json:"_"` // set from context
	}
)

func (ni *NullableInt) UnmarshalJSON(b []byte) error {
	ni.Set = true
	if string(b) == "null" {
		ni.Value = nil
		return nil
	}
	var v int
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	ni.Value = &v
	return nil
}

func (u UserV3) GetID() interface{} {
	return u.ID
}

func (u *UserV3) GenID() {
	if u.ID.IsZero() {
		u.ID = primitive.NewObjectID()
	}
}

// Helper function to build common match logic - reduces duplication
func buildCommonMatchLogic(keyword string, country, packageFilter []string, fromExpired, toExpired, fromEffective, toEffective int64) bson.M {
	query := bson.M{}

	// Filter username or phone
	if strings.TrimSpace(keyword) != "" {
		query["$or"] = []bson.M{
			{"username": bson.M{"$regex": keyword, "$options": "i"}},
			{"phone": bson.M{"$regex": keyword, "$options": "i"}},
		}
	}

	// Filter country
	if len(country) > 0 {
		query["country"] = bson.M{"$in": country}
	}

	// Filter package for roles
	if len(packageFilter) > 0 {
		query["package"] = bson.M{"$in": packageFilter}
	}

	// Expired time range
	if fromExpired > 0 || toExpired > 0 {
		timeFilter := bson.M{}
		if fromExpired > 0 {
			timeFilter["$gte"] = fromExpired
		}
		if toExpired > 0 {
			timeFilter["$lte"] = toExpired
		}
		query["expired_time"] = timeFilter
	}

	// Effective time range
	if fromEffective > 0 || toEffective > 0 {
		timeFilter := bson.M{}
		if fromEffective > 0 {
			timeFilter["$gte"] = fromEffective
		}
		if toEffective > 0 {
			timeFilter["$lte"] = toEffective
		}
		query["effective_time"] = timeFilter
	}

	return query
}

func (s *SearchUserV3) BuildMatch() bson.M {
	// Use common logic then add specific filters
	query := buildCommonMatchLogic(s.Keyword, s.Country, s.Package, s.FromExpiredTime, s.ToExpiredTime, s.FromEffectiveTime, s.ToEffectiveTime)

	// Add SearchUserV3 specific filters
	if len(s.Organization) > 0 {
		query["group_id"] = bson.M{"$in": s.Organization}
	}

	if len(s.Active) > 0 {
		query["active"] = bson.M{"$in": s.Active}
	}

	if len(s.Ownership) > 0 {
		query["ownership"] = bson.M{"$in": s.Ownership}
	}

	if len(s.Mass) > 0 {
		query["mass"] = bson.M{"$in": s.Mass}
	}

	return query
}

func (s *SearchUserV3StatisticRequest) BuildMatch() bson.M {
	// Use same common logic - ensures identical behavior
	query := buildCommonMatchLogic(s.Keyword, s.Country, s.Package, s.FromExpiredTime, s.ToExpiredTime, s.FromEffectiveTime, s.ToEffectiveTime)
	// Add SearchUserV3 specific filters
	if len(s.Organization) > 0 {
		query["group_id"] = bson.M{"$in": s.Organization}
	}
	return query
}

// Helper to build common pipeline stages - reduces duplication
func buildCommonPipelineStages() []*bson.M {
	pipeline := make([]*bson.M, 0)

	// Lookup group_user
	pipeline = append(pipeline, buildLookupStage("group_user", "group_id", "_id", "group_info"))
	pipeline = append(pipeline, buildUnwindStage("$group_info"))

	// Lookup roles - EXACTLY as original
	pipeline = append(pipeline, buildLookupStage("roles", "group_info.role", "role_id", "role_info"))
	pipeline = append(pipeline, buildUnwindStage("$role_info"))

	// addFields để flatten data - EXACTLY as original
	pipeline = append(pipeline, &bson.M{
		"$addFields": bson.M{
			"effective_time": "$group_info.effective_time",
			"expired_time":   "$group_info.expired_time",
			"name":           "$group_info.name",
			"package":        "$role_info.description",
			"mass":           "$role_info.mass",
			"role":           "$role_info.role_id",
			"tenant_id":      "$group_info.tenant_id",
		},
	})

	// xử lý mfa_properties
	pipeline = append(pipeline, buildMfaPropertiesStage())

	// project để bỏ field lookup
	pipeline = append(pipeline, &bson.M{
		"$project": bson.M{
			"group_info": 0,
			"role_info":  0,
		},
	})

	return pipeline
}

func (s *SearchUserV3) BuildPipeline(offset, size int64, sorts []bson.M) []*bson.M {
	// Use common pipeline stages
	pipeline := buildCommonPipelineStages()

	// match conditions
	match := s.BuildMatch()
	if len(match) > 0 {
		pipeline = append(pipeline, &bson.M{"$match": match})
	}

	// build sort stage - EXACTLY as original
	sortStage := bson.M{}
	if len(sorts) > 0 {
		for _, sort := range sorts {
			for k, v := range sort {
				sortStage[k] = v
			}
		}
	} else {
		sortStage["created_time"] = -1
	}

	// facet stage - EXACTLY as original
	facet := bson.M{
		"$facet": bson.M{
			"data": []bson.M{
				{"$sort": sortStage},
				{"$skip": offset},
				{"$limit": size},
			},
			"total": []bson.M{
				{"$count": "count"},
			},
		},
	}
	pipeline = append(pipeline, &facet)

	return pipeline
}

func (s *SearchUserV3) BuildPagination() (int64, int64) {
	size := s.Size
	offset := s.Offset

	if size <= 0 {
		size = 10
	}
	if offset < 0 {
		offset = 0
	}
	return offset, size
}

func (g *GetUserDetailV3) BuildPipeline() []*bson.M {
	pipeline := make([]*bson.M, 0)

	// Match user by ID first - EXACTLY as original
	pipeline = append(pipeline, &bson.M{"$match": bson.M{"_id": g.ID}})

	// Lookup group_user - EXACTLY as original
	pipeline = append(pipeline, buildLookupStage("group_user", "group_id", "_id", "group_info"))
	pipeline = append(pipeline, buildUnwindStage("$group_info"))

	// Lookup roles - CRITICAL: Different from SearchUserV3! Uses "group_info.role"
	pipeline = append(pipeline, buildLookupStage("roles", "group_info.role", "role_id", "role_info"))
	pipeline = append(pipeline, buildUnwindStage("$role_info"))

	// Flatten data - EXACTLY as original
	pipeline = append(pipeline, &bson.M{
		"$addFields": bson.M{
			"effective_time": "$group_info.effective_time",
			"expired_time":   "$group_info.expired_time",
			"tenant_id":      "$group_info.tenant_id",
			"package":        "$role_info.description",
			"mass":           "$role_info.mass",
		},
	})

	// Xử lý mfa_properties - EXACTLY as original
	pipeline = append(pipeline, buildMfaPropertiesStage())

	// Project để bỏ field lookup - EXACTLY as original
	pipeline = append(pipeline, &bson.M{
		"$project": bson.M{
			"group_info": 0,
			"role_info":  0,
		},
	})

	// Limit 1 - EXACTLY as original
	pipeline = append(pipeline, &bson.M{"$limit": 1})

	return pipeline
}

func (s *SearchUserV3StatisticRequest) BuildPipeline() []*bson.M {
	// Use common pipeline stages (same as SearchUserV3)
	pipeline := buildCommonPipelineStages()

	// Match stage - EXACTLY as original
	match := s.BuildMatch()
	if len(match) > 0 {
		pipeline = append(pipeline, &bson.M{"$match": match})

	}

	// Facet stage cho thống kê - thêm $match để lọc "" và null
	pipeline = append(pipeline, &bson.M{
		"$facet": bson.M{
			"status": []bson.M{
				{"$group": bson.M{"_id": "$active", "count": bson.M{"$sum": 1}}},
			},
			"ownership": []bson.M{
				{"$group": bson.M{"_id": "$ownership", "count": bson.M{"$sum": 1}}},
			},
			"type": []bson.M{
				{"$group": bson.M{"_id": "$mass", "count": bson.M{"$sum": 1}}},
			},
			"country": []bson.M{
				// lọc bỏ null hoặc ""
				{"$match": bson.M{"country": bson.M{"$nin": []interface{}{"", nil}}}},
				{"$group": bson.M{"_id": nil, "values": bson.M{"$addToSet": "$country"}}},
				{"$project": bson.M{"_id": 0, "values": 1}},
			},
			"package": []bson.M{
				// lọc bỏ null hoặc ""
				{"$match": bson.M{"package": bson.M{"$nin": []interface{}{"", nil}}}},
				{"$group": bson.M{"_id": nil, "values": bson.M{"$addToSet": "$package"}}},
				{"$project": bson.M{"_id": 0, "values": 1}},
			},
		},
	})

	return pipeline
}

// Helper functions - EXACTLY as original
func buildLookupStage(from, localField, foreignField, as string) *bson.M {
	return &bson.M{
		"$lookup": bson.M{
			"from":         from,
			"localField":   localField,
			"foreignField": foreignField,
			"as":           as,
		},
	}
}

func buildUnwindStage(path string) *bson.M {
	return &bson.M{
		"$unwind": bson.M{
			"path":                       path,
			"preserveNullAndEmptyArrays": true,
		},
	}
}

func buildMfaPropertiesStage() *bson.M {
	return &bson.M{
		"$addFields": bson.M{
			"mfa_enabled": bson.M{
				"$cond": bson.A{
					bson.M{
						"$gt": bson.A{
							bson.M{
								"$size": bson.M{
									"$ifNull": bson.A{"$mfa_properties", bson.A{}},
								},
							},
							0,
						},
					},
					bson.M{
						"$allElementsTrue": bson.M{
							"$map": bson.M{
								"input": "$mfa_properties",
								"as":    "mfa",
								"in":    "$$mfa.enable",
							},
						},
					},
					false,
				},
			},
		},
	}
}
