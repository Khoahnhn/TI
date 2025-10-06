package model

import (
	"strings"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"go.mongodb.org/mongo-driver/bson"
)

type (
	User struct {
		ID                string `json:"id" bson:"_id"`
		Username          string `json:"username" bson:"username"`
		Active            bool   `json:"active" bson:"active"`
		GroupID           string `json:"group_id" bson:"group_id"`
		APIKey            string `json:"api_key" bson:"api_key"`
		APIKeyExpiredTime int64  `json:"api_key_expired_time" bson:"api_key_expired_time"`
		Language          string `json:"language" bson:"language"`
		FirstName         string `json:"first_name" bson:"first_name"`
		LastName          string `json:"last_name" bson:"last_name"`
		CompanyName       string `json:"company_name" bson:"company_name"`
		Phone             string `json:"phone" bson:"phone"`
		CompanySize       string `json:"company_size" bson:"company_size"`
		Country           string `json:"country" bson:"country"`
		Position          int    `json:"position" bson:"position"`
		GroupRole         `bson:",inline"`
	}
	UpdatePublicUserDTO struct {
		FirstName string `json:"first_name" bson:"first_name"`
		LastName  string `json:"last_name" bson:"last_name"`
		Phone     string `json:"phone" bson:"phone"`
		Status    bool   `json:"status" bson:"active"`
		GroupRole `bson:",inline"`
	}
	CreatePublicUserDTO struct {
		Email               string `json:"email" bson:"username"`
		UpdatePublicUserDTO `bson:",inline"`
	}
	PublicUser struct {
		ID                  string        `json:"id" bson:"_id"`
		Email               string        `json:"email" bson:"username"`
		LastActivity        int64         `json:"last_activity" bson:"last_activity"` //
		TwoFA               bool          `json:"two_fa" bson:"-"`
		MFaProperties       []MFaProperty `json:"-" bson:"mfa_properties"`
		UpdatePublicUserDTO `bson:",inline"`
	}
	MFaProperty struct {
		Enable    bool   `bson:"enable"`
		Type      string `bson:"type"`
		Timestamp int64  `bson:"timestamp"`
	}
	SearchUser struct {
		SearchUserStatistic
		GroupRole []string `json:"group_role"` //
		Offset    int64    `json:"offset"`
		Size      int64    `json:"size"`
		TwoFA     []bool   `json:"two_fa"`
	}
	SearchUserStatistic struct {
		Keyword          string `json:"keyword"`
		LastActivityFrom int64  `json:"last_activity_from"` //
		LastActivityTo   int64  `json:"last_activity_to"`   //
	}
	GroupRole struct {
		GroupRole string `json:"group_role" bson:"group_role"` //
	}
)

type APIResponse struct {
	Code    defs.StatusCode `json:"code"`
	Message string          `json:"message"`
	Data    any             `json:"data,omitempty"`
	Errors  []APIError      `json:"errors,omitempty"`
	Total   int64           `json:"total,omitempty"`
}
type APIError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type PPUserInfo struct {
	OrgId        string
	OrgName      string
	UserId       string
	UserFullname string
}

type SearchStatisticResponseAggs struct {
	TwoFA []*AggBoolFieldValue   `json:"two_fa"`
	Role  []*AggStringFieldValue `json:"group_role"`
}

type AggStringFieldValue struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type AggBoolFieldValue struct {
	Value bool  `json:"value" bson:"_id"`
	Count int64 `json:"count" bson:"count"`
}

func (s *SearchUserStatistic) BuildQuery(org string) bson.M {
	query := bson.M{
		"group_id": org,
	}

	if s.Keyword != "" {
		query["$or"] = []bson.M{
			{"username": bson.M{"$regex": s.Keyword, "$options": "i"}},
			{"phone": bson.M{"$regex": s.Keyword, "$options": "i"}},
		}
	}

	if s.LastActivityFrom > 0 || s.LastActivityTo > 0 {
		timeFilter := bson.M{}
		if s.LastActivityFrom > 0 {
			timeFilter["$gte"] = s.LastActivityFrom
		}
		if s.LastActivityTo > 0 {
			timeFilter["$lte"] = s.LastActivityTo
		}
		query["last_activity"] = timeFilter
	}
	return query
}

func (s *SearchUser) BuildQuery(org string) bson.M {
	keyword := strings.TrimSpace(s.Keyword)
	query := bson.M{
		"group_id": org,
	}

	if s.Keyword != "" {
		query["$or"] = []bson.M{
			{"username": bson.M{"$regex": keyword, "$options": "i"}},
			{"phone": bson.M{"$regex": keyword, "$options": "i"}},
		}
	}

	if s.LastActivityFrom > 0 || s.LastActivityTo > 0 {
		timeFilter := bson.M{}
		if s.LastActivityFrom > 0 {
			timeFilter["$gte"] = s.LastActivityFrom
		}
		if s.LastActivityTo > 0 {
			timeFilter["$lte"] = s.LastActivityTo
		}
		query["last_activity"] = timeFilter
	}

	if len(s.GroupRole) > 0 {
		if contains(s.GroupRole, "user") {
			query["$or"] = []bson.M{
				{"group_role": bson.M{"$in": s.GroupRole}},
				{"group_role": bson.M{"$exists": false}},
			}
		} else {
			query["group_role"] = bson.M{"$in": s.GroupRole}
		}
	}

	if len(s.TwoFA) == 1 {
		mfa_query := bson.M{
			"$elemMatch": bson.M{
				"enable": true,
			},
		}
		if s.TwoFA[0] == true {
			query["mfa_properties"] = mfa_query
		} else {
			query["mfa_properties"] = bson.M{
				"$not": mfa_query,
			}
		}
	}

	return query
}

func contains(arr []string, str string) bool {
	for _, v := range arr {
		if v == str {
			return true
		}
	}
	return false
}

func (s *SearchUser) BuildPagination() (int64, int64) {
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
