package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestUserHistory_GetIDAndGenID(t *testing.T) {
	h := &UserHistory{}
	assert.True(t, h.ID.IsZero())

	// GenID sẽ gán ObjectID mới
	h.GenID()
	assert.False(t, h.ID.IsZero())
	assert.Equal(t, h.ID, h.GetID())
}

func TestUserHistory_SetTimestamps(t *testing.T) {
	h := &UserHistory{}
	assert.Equal(t, int64(0), h.CreatedTime)

	h.SetTimestamps()
	assert.NotEqual(t, int64(0), h.CreatedTime)

	// Nếu đã có timestamp thì vẫn override thành now
	old := h.CreatedTime
	time.Sleep(1 * time.Second)
	h.SetTimestamps()
	assert.Greater(t, h.CreatedTime, old)
}

func TestSearchUserHistory_BuildPagination(t *testing.T) {
	h := &SearchUserHistory{Size: 0, Offset: -1}
	offset, size := h.BuildPagination()
	assert.Equal(t, int64(0), offset)
	assert.Equal(t, int64(10), size)

	h = &SearchUserHistory{Size: 5, Offset: 2}
	offset, size = h.BuildPagination()
	assert.Equal(t, int64(2), offset)
	assert.Equal(t, int64(5), size)
}

func TestSearchUserHistory_BuildPipeline_WithID(t *testing.T) {
	id := primitive.NewObjectID()
	h := &SearchUserHistory{ID: &id}

	pipeline := h.BuildPipeline(0, 10, nil)
	assert.NotEmpty(t, pipeline)

	// Stage $match phải có _id
	matchStage := (*pipeline[0])["$match"].(bson.M)
	assert.Equal(t, id, matchStage["_id"])
}

func TestSearchUserHistory_BuildPipeline_WithUserID(t *testing.T) {
	uid := primitive.NewObjectID()
	h := &SearchUserHistory{UserID: &uid}

	pipeline := h.BuildPipeline(0, 10, nil)
	assert.NotEmpty(t, pipeline)

	// Stage $match phải có user_id
	matchStage := (*pipeline[0])["$match"].(bson.M)
	assert.Equal(t, uid, matchStage["user_id"])

	// Stage $project phải loại bỏ user_before, user_after
	foundProject := false
	for _, stage := range pipeline {
		if proj, ok := (*stage)["$project"]; ok {
			foundProject = true
			p := proj.(bson.M)
			assert.Equal(t, 0, p["user_before"])
			assert.Equal(t, 0, p["user_after"])
		}
	}
	assert.True(t, foundProject)
}

func TestSearchUserHistory_BuildPipeline_SortAndFacet(t *testing.T) {
	h := &SearchUserHistory{}
	sorts := []bson.M{{"created_time": -1}}
	pipeline := h.BuildPipeline(5, 20, sorts)

	// Stage cuối cùng phải có facet
	lastStage := *pipeline[len(pipeline)-1]
	facet := lastStage["$facet"].(bson.M)

	// Check data stage
	dataStage := facet["data"].([]bson.M)
	assert.Contains(t, dataStage[0], "$sort")
	assert.Contains(t, dataStage[1], "$skip")
	assert.Contains(t, dataStage[2], "$limit")

	// Check total stage
	totalStage := facet["total"].([]bson.M)
	assert.Equal(t, "count", totalStage[0]["$count"])
}
