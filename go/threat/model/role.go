package model

type Role struct {
	ID          string   `json:"id" bson:"id"`
	RoleID      string   `json:"role_id" bson:"role_id"`
	Permissions []string `json:"permissions" bson:"permissions"`
	Description string   `json:"description" bson:"description"`
	Month       int      `json:"month" bson:"month"`
	Mass        bool     `json:"mass" bson:"mass"`
}
