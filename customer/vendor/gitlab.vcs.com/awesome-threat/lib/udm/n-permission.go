package udm

type Permission struct {
	Description string         `json:"description,omitempty"`
	Name        string         `json:"name,omitempty"`
	Type        PermissionType `json:"type,omitempty"`
}
