package handler

import (
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	mockOrg = model.Organization{
		Id:          "org_1",
		Name:        "outsource",
		Description: "outsource",
	}
	mockRoleDetail = model.Role{
		ID:           "xxxxxxxxxxxxxxxx",
		RoleID:       "extreme",
		LimitAccount: 1,
		Permissions:  []string{string(defs.PermissionPremium)},
	}
	mockUser = model.UserV3{
		ID:       primitive.NewObjectID(),
		Username: "hoantv16@viettel.com.vn",
		GroupID:  "org_1",
		Active:   true,
	}
	mockUserDetail = model.UserV3Aggregate{
		UserV3:   mockUser,
		RoleMass: false,
	}
)
