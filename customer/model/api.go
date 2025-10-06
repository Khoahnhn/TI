package model

type (
	ApiOpV1PublicUserPostResponse struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
	}

	ApiOpV1CreatePublicUserRequest struct {
		Username    string `json:"username"`
		Phone       string `json:"phone"`
		Country     string `json:"country"`
		CompanyName string `json:"company_name"`
		CompanySize string `json:"company_size"`
		FirstName   string `json:"first_name"`
		LastName    string `json:"last_name"`
		Position    int    `json:"position"`
		Active      bool   `json:"active"`
		GroupId     string `json:"group_id"`
		Language    string `json:"language"`
		GroupRole   string `json:"group_role,omitempty"`
	}
)
