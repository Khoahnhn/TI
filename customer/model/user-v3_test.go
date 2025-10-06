package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// helper để stringify pipeline dễ so sánh
func toJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func TestUserV3_GetIDAndGenID(t *testing.T) {
	u := UserV3{}
	assert.True(t, u.ID.IsZero())

	// GenID sẽ gán ObjectID mới
	u.GenID()
	assert.False(t, u.ID.IsZero())
	assert.Equal(t, u.ID, u.GetID())
}

func TestSearchUserV3_BuildMatch(t *testing.T) {
	s := SearchUserV3{
		Keyword:           "john",
		Country:           []string{"VN", "US"},
		Package:           []string{"pkg1"},
		Organization:      []string{"org1"},
		Active:            []bool{true},
		Ownership:         []bool{false},
		Mass:              []bool{true},
		FromExpiredTime:   100,
		ToExpiredTime:     200,
		FromEffectiveTime: 300,
		ToEffectiveTime:   400,
	}

	q := s.BuildMatch()

	//  Check keyword regex
	orConds, ok := q["$or"].([]bson.M)
	assert.True(t, ok)
	assert.Equal(t, 2, len(orConds))
	assert.Equal(t, bson.M{"$regex": "john", "$options": "i"}, orConds[0]["username"])
	assert.Equal(t, bson.M{"$regex": "john", "$options": "i"}, orConds[1]["phone"])

	//  Check group_id
	assert.Equal(t, bson.M{"$in": []string{"org1"}}, q["group_id"])

	//  Check country
	assert.Equal(t, bson.M{"$in": []string{"VN", "US"}}, q["country"])

	//  Check package
	assert.Equal(t, bson.M{"$in": []string{"pkg1"}}, q["package"])

	//  Check active
	assert.Equal(t, bson.M{"$in": []bool{true}}, q["active"])

	//  Check ownership
	assert.Equal(t, bson.M{"$in": []bool{false}}, q["ownership"])

	//  Check mass
	assert.Equal(t, bson.M{"$in": []bool{true}}, q["mass"])

	//  Check expired_time
	assert.Equal(t, bson.M{"$gte": int64(100), "$lte": int64(200)}, q["expired_time"])

	//  Check effective_time
	assert.Equal(t, bson.M{"$gte": int64(300), "$lte": int64(400)}, q["effective_time"])
}

func TestSearchUserV3_BuildPagination(t *testing.T) {
	s := SearchUserV3{Size: 0, Offset: -1}
	offset, size := s.BuildPagination()
	assert.Equal(t, int64(0), offset)
	assert.Equal(t, int64(10), size)

	s = SearchUserV3{Size: 5, Offset: 2}
	offset, size = s.BuildPagination()
	assert.Equal(t, int64(2), offset)
	assert.Equal(t, int64(5), size)
}

func TestSearchUserV3_BuildPipeline(t *testing.T) {
	s := SearchUserV3{Keyword: "abc", Size: 5, Offset: 0}
	pipeline := s.BuildPipeline(0, 5, nil)

	js := toJSON(pipeline)
	assert.Contains(t, js, "$lookup")
	assert.Contains(t, js, "$facet")
	assert.Contains(t, js, "created_time")
}

func TestGetUserDetailV3_BuildPipeline(t *testing.T) {
	id := primitive.NewObjectID()
	g := GetUserDetailV3{ID: id}
	pipeline := g.BuildPipeline()

	js := toJSON(pipeline)
	assert.Contains(t, js, id.Hex())
	assert.Contains(t, js, "group_info.role") // check lookup khác biệt
}

func TestSearchUserV3StatisticRequest_BuildMatch(t *testing.T) {
	s := SearchUserV3StatisticRequest{
		Keyword:         "phone123",
		Country:         []string{"JP"},
		Package:         []string{"basic"},
		FromExpiredTime: 111,
		ToExpiredTime:   222,
	}

	q := s.BuildMatch()
	js := toJSON(q)

	assert.Contains(t, js, "phone")
	assert.Contains(t, js, "basic")
	assert.Contains(t, js, "expired_time")
}

func TestSearchUserV3StatisticRequest_BuildPipeline(t *testing.T) {
	s := SearchUserV3StatisticRequest{Keyword: "test"}
	pipeline := s.BuildPipeline()

	js := toJSON(pipeline)
	assert.Contains(t, js, "$facet")
	assert.Contains(t, js, "status")
	assert.Contains(t, js, "ownership")
	assert.Contains(t, js, "package")
}

func TestHelperStages(t *testing.T) {
	lookup := buildLookupStage("roles", "role", "role_id", "role_info")
	unwind := buildUnwindStage("$role_info")
	mfa := buildMfaPropertiesStage()

	assert.Contains(t, toJSON(lookup), "roles")
	assert.Contains(t, toJSON(unwind), "role_info")
	assert.Contains(t, toJSON(mfa), "mfa_properties")
}
