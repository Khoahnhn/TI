package model

import (
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"regexp"
	"time"

	"gitlab.viettelcyber.com/awesome-threat/library/hash"
)

type (
	Feature struct {
		ID          string   `bson:"_id,omitempty" json:"id"`
		Name        string   `bson:"name" json:"name"`
		Code        string   `bson:"code" json:"code"`
		Description string   `bson:"description,omitempty" json:"description,omitempty"`
		Weight      int      `json:"weight" bson:"weight"`
		Actions     []string `bson:"actions,omitempty" json:"actions,omitempty"`
		ParentID    string   `bson:"parent_id,omitempty" json:"parent_id,omitempty"`
		Ancestors   []string `bson:"ancestors" json:"ancestors"`
		Creator     string   `bson:"creator" json:"creator"`
		CreatedAt   int64    `bson:"created_at" json:"created_at"`
		Editor      string   `bson:"editor,omitempty" json:"editor,omitempty"`
		UpdatedAt   int64    `bson:"updated_at,omitempty" json:"updated_at,omitempty"`
	}

	RequestCreateFeature struct {
		Name          string   `json:"name" mod:"trim" validate:"required"`
		Code          string   `json:"code" mod:"trim" validate:"required"`
		Description   string   `json:"description" mod:"trim"`
		ParentFeature string   `json:"parent_feature" mod:"trim"`
		Permissions   []string `json:"permissions" mod:"trim" validate:"dive,oneof=create update read delete"`
		Weight        int      `json:"weight" mod:"trim" validate:"required,gte=1,lte=1000"`
	}

	RequestEditFeature struct {
		ID            string   `param:"id" mod:"trim" validate:"required"` //code
		Name          string   `json:"name" mod:"trim" validate:"required"`
		Description   string   `json:"description" mod:"trim"`
		ParentFeature string   `json:"parent_feature" mod:"trim"`
		Permissions   []string `json:"permissions" mod:"trim" validate:"dive,oneof=create update read delete"`
		Weight        int      `json:"weight" mod:"trim" validate:"required,gte=1,lte=1000"`
	}

	RequestCode struct {
		ID string `param:"id" mod:"trim" validate:"required"` //code
	}

	FeatureWithPermissions struct {
		Feature     `bson:",inline"`
		Children    []*FeatureWithPermissions `bson:"-" json:"children,omitempty"`
		Permissions []*PermissionsResponse    `bson:"permissions" json:"permissions"`
	}

	RequestFeatureList struct {
		Keyword       string   `json:"keyword" mod:"trim"`
		ParentFeature string   `json:"parent_feature" mod:"trim"`
		FeatureCode   string   `json:"feature_code" mod:"trim"`
		Sort          []string `json:"sort"`
		Size          int64    `json:"size" validate:"numeric,gte=0"`
		Offset        int64    `json:"offset" validate:"numeric,gte=0"`
	}
)

func (doc *Feature) GetID() interface{} {
	// Success
	return doc.ID
}

func (doc *Feature) GenID() {
	now := time.Now().UnixNano()
	// Success
	doc.ID = hash.SHA1(fmt.Sprintf("%s--%v", doc.Name, now))
}

func (body *RequestFeatureList) Query() *bson.M {
	filter := bson.M{}
	if body.Keyword != "" {
		regexSearch := regexp.QuoteMeta(body.Keyword)
		filter["$or"] = bson.A{
			bson.M{"name": bson.M{"$regex": regexSearch, "$options": "i"}},
			bson.M{"code": bson.M{"$regex": regexSearch, "$options": "i"}},
		}
	}
	if body.ParentFeature != "" {
		filter["ancestors"] = body.ParentFeature
	}
	if len(filter) == 0 {
		return &bson.M{}
	}
	// Success
	return &filter
}
