package model

type (
	RequestPaging struct {
		PageSize int `json:"page_size"`
		Offset   int `json:"offset"`
	}

	RequestTimeInterval struct {
		StartTime int64 `json:"start_time"`
		EndTime   int64 `json:"end_time"`
	}
)
