package model

import (
	"time"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type (
	UserHistory struct {
		ID          primitive.ObjectID `json:"id" bson:"_id"`
		UserID      primitive.ObjectID `json:"user_id" bson:"user_id"`
		Event       defs.HistoryEvent  `json:"event" bson:"event"`
		UserBefore  string             `json:"user_before,omitempty" bson:"user_before,omitempty" `
		UserAfter   string             `json:"user_after,omitempty" bson:"user_after,omitempty"`
		CreatedTime int64              `json:"created_time" bson:"created_time"`
		Creator     string             `json:"creator" bson:"creator"`
		Action      string             `json:"action,omitempty" bson:"action,omitempty"`
	}

	SearchUserHistory struct {
		ID     *primitive.ObjectID `json:"-" bson:"_id"`
		UserID *primitive.ObjectID `json:"-" bson:"user_id"`
		Offset int64               `json:"offset" query:"offset" bson:"offset"`
		Size   int64               `json:"size" query:"size" bson:"size"`
	}

	CreateUserHistoryDTO struct {
		UserID  primitive.ObjectID
		Event   defs.HistoryEvent
		Before  map[string]any
		After   map[string]any
		Creator string
	}
)

func (h *UserHistory) GetID() interface{} {
	return h.ID
}

func (h *UserHistory) GenID() {
	if h.ID.IsZero() {
		h.ID = primitive.NewObjectID()
	}
}

func (h *UserHistory) SetTimestamps() {
	now := time.Now().Unix()
	if h.CreatedTime == 0 {
		h.CreatedTime = now
	}
	h.CreatedTime = now
}

func (h *SearchUserHistory) BuildPagination() (int64, int64) {
	size := h.Size
	offset := h.Offset

	if size <= 0 {
		size = 10
	}
	if offset < 0 {
		offset = 0
	}
	return offset, size
}
func (h *SearchUserHistory) BuildPipeline(offset, size int64, sorts []bson.M) []*bson.M {
	pipeline := make([]*bson.M, 0)

	match := bson.M{}

	if h.ID != nil {
		match["_id"] = *h.ID
	}

	if h.UserID != nil {
		match["user_id"] = *h.UserID
	}

	if len(match) > 0 {
		pipeline = append(pipeline, &bson.M{
			"$match": match,
		})
	}

	if h.UserID != nil && h.ID == nil {
		pipeline = append(pipeline, &bson.M{
			"$project": bson.M{
				"user_before": 0,
				"user_after":  0,
			},
		})
	}

	sortStage := bson.M{}
	if len(sorts) > 0 {
		for _, s := range sorts {
			for k, v := range s {
				sortStage[k] = v
			}
		}
	} else {
		sortStage["created_time"] = 1
	}

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
