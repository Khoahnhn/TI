package model

import "time"

type (
	ProductDetail struct {
		ID      string `json:"id" bson:"id"`
		Owner   string `json:"owner" bson:"owner"`
		Product string `json:"product" bson:"product"`
		Version string `json:"version" bson:"version"`
		Update  string `json:"update" bson:"update"`
	}

	Product struct {
		ProductDetail
		Created time.Time `json:"creation_time" bson:"creation_time"`
		Value   string    `json:"value" bson:"value"`
		Cpe     string    `json:"cpe" bson:"cpe"`
	}
)
