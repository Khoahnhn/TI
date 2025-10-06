package model

type Group struct {
	ID          string   `json:"id,omitempty"`
	TenantID    string   `json:"tenant_id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Active      bool     `json:"active,omitempty"`
	ExpiredTime int64    `json:"expired_time,omitempty"`
	Role        string   `json:"role,omitempty"`
	Parent      string   `json:"parent,omitempty"`
	Ancestors   []string `json:"ancestors,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Industry    []string `json:"industry,omitempty"`
}

type GetGroupResponse struct {
	Success bool   `json:"success,omitempty"`
	Message string `json:"message,omitempty"`
	Detail  Group  `json:"detail"`
}
