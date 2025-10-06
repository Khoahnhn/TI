package model

import (
	"regexp"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
)

type (
	RequestCustomerOrganizationGet struct {
		ID string `json:"id" param:"id"`
	}

	RequestCustomerOrganizationSearch struct {
		Name        string   `json:"name"`
		Type        string   `json:"type"`
		Active      string   `json:"active"`
		Roles       []string `json:"roles"`
		Permissions []string `json:"permissions"`
		Sorts       []string `json:"sorts"`
		Offset      int64    `json:"offset"`
		Size        int64    `json:"size"`
		IsEasm      bool     `json:"is_easm"`
	}
)

func (body *RequestCustomerOrganizationGet) Query() *bson.M {
	filter := bson.M{}
	filter["$or"] = []interface{}{
		bson.M{"_id": body.ID},
		bson.M{"tenant_id": body.ID},
	}
	// Success
	return &filter
}

func (body *RequestCustomerOrganizationSearch) Query() *bson.M {
	filter := bson.M{}
	if body.Name != "" {
		regex := regexp.QuoteMeta(body.Name)
		filter["tenant_id"] = bson.M{"$regex": regex, "$options": "i"}
	}
	if body.Active != "" {
		if value, ok := defs.MappingCustomerActive[body.Active]; ok {
			filter["active"] = value
		}
		if body.Active == defs.CustomerActive {
			now, _ := clock.Now(clock.Local)
			// include TI MASS tenants (expired_time == 0)
			filter["$or"] = bson.A{
				bson.M{"expired_time": 0},
				bson.M{"expired_time": bson.M{"$gte": clock.Unix(now)}},
			}
		}
	}
	if len(body.Roles) > 0 {
		filter["role"] = bson.M{"$in": body.Roles}
	}
	// Success
	return &filter
}

func (body *RequestCustomerOrganizationSearch) QueryRolesByPermissions() *bson.M {
	filter := bson.M{}
	filter["permissions"] = bson.M{"$in": body.Permissions}
	// Success
	return &filter
}

func (body *RequestCustomerOrganizationSearch) CombineRole(roles []*Role) {
	if len(body.Roles) == 0 {
		if len(roles) > 0 {
			body.Roles = make([]string, 0)
			for _, role := range body.Roles {
				body.Roles = append(body.Roles, role)
			}
		}
	} else {
		results := make([]string, 0)
		for _, role := range roles {
			if slice.String(body.Roles).Contains(role.RoleID) {
				results = append(results, role.RoleID)
			}
		}
		body.Roles = results
	}
}
