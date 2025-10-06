package virustotal

type (
	ResponseMeta struct {
		Count  int64  `json:"count,omitempty"`
		Cursor string `json:"cursor,omitempty"`
	}

	ResponseLinks struct {
		Self string `json:"self,omitempty"`
		Next string `json:"next,omitempty"`
	}
)
