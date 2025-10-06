package model

import (
	"fmt"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"go.mongodb.org/mongo-driver/bson"
	"regexp"
)

type (
	Permissions struct {
		ID           string `bson:"_id,omitempty" json:"id"`
		PermissionId string `bson:"permission_id" json:"permission_id"`
		Description  string `bson:"description" json:"description"`
		ModifiedTime int64  `bson:"modified_time" json:"modified_time"`
		ModuleID     string `bson:"module_id" json:"module_id"`
	}

	RequestGetPermissions struct {
		Module   string `json:"module" mod:"trim"`
		Keyword  string `json:"keyword" mod:"trim"`
		IsModule bool   `json:"is_module" mod:"trim"`
		Size     int64  `json:"size" validate:"numeric,gte=0"`
		Offset   int64  `json:"offset" validate:"numeric,gte=0"`
	}

	RequestUpdatePermission struct {
		ID          string `param:"id" mod:"trim" validate:"required"`
		Description string `json:"description" mod:"trim"`
		Module      string `json:"module" mod:"trim" validate:"required"`
	}

	UpdatePermission struct {
		Description string
		ModuleID    string
	}

	RequestUpdateModule struct {
		IDs       []string `json:"ids"`
		NewModule string   `json:"new_module" validate:"required"`
	}

	UpdateFeature struct {
		IDs       []string
		FeatureID string
	}

	FeatureResponse struct {
		ID   string `bson:"_id" json:"id"`
		Name string `bson:"name" json:"name"`
	}

	PermissionsResponse struct {
		ID           string `bson:"_id,omitempty" json:"id"`
		PermissionID string `bson:"permission_id" json:"permission_id"`
		Description  string `bson:"description,omitempty" json:"description"`
		ModifiedTime int64  `bson:"modified_time,omitempty" json:"modified_time,omitempty"`
	}

	PermissionWithModule struct {
		PermissionsResponse `bson:",inline"`
		Module              FeatureResponse `bson:"module" json:"module"`
	}
)

func (s *RequestGetPermissions) BuildQuery() bson.M {
	query := bson.M{}
	if s.Module != "" {
		query["module_id"] = s.Module
	}
	if s.Keyword != "" {
		s.Keyword = regexp.QuoteMeta(s.Keyword)
		query["$or"] = []bson.M{
			{"permission_id": bson.M{"$regex": s.Keyword, "$options": "i"}},
			{"description": bson.M{"$regex": s.Keyword, "$options": "i"}},
		}
	}
	return query
}

func (s *RequestGetPermissions) BuildPagination() (int64, int64) {
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

func (doc *Permissions) GetID() string {
	// Success
	return doc.ID
}

func (doc *Permissions) GenID() {
	// Success
	doc.ID = hash.SHA1(fmt.Sprintf("%s", doc.PermissionId))
}
