package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/labstack/echo/v4"
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

func (inst *ManagerUserHandler) GetOrganization(c echo.Context) error {
	body, err := inst.verifyGetOrganization(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	result, err := inst.mongo.Account().GroupUser().Get(context.Background(), body.ID)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusNotFound).Log(err).Go()
	}
	if result.Role == "" {
		return rest.JSON(c).Code(rest.StatusNotFound).Log(errors.New("role not found")).Go()
	}
	role, err := inst.mongo.Account().Roles().GetByName(context.Background(), result.Role)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusNotFound).Log(err).Go()
	}
	result.Permissions = role.Permissions
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(result).Go()
}

func (inst *ManagerUserHandler) SearchOrganization(c echo.Context) error {
	body, err := inst.verifySearchOrganization(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.Query()
	inst.searchEasmOrganization(c.Request().Context(), body, query)
	documents := make([]*model.GroupUser, 0)
	results := make([]*model.GroupUserSummary, 0)
	switch body.Type {
	case defs.CustomerTypeAll:
		results = append(results, model.GroupIndustries...)
	case defs.CustomerTypeIndustry:
		results = append(results, model.GroupIndustries...)
		// Success
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results, "total": len(results)}).Go()
	}

	if len(body.Permissions) > 0 {
		roles, err := inst.mongo.Account().Roles().FindAll(context.Background(), body.QueryRolesByPermissions(), []string{})
		if err != nil {
			if err.Error() != mg.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			roles = make([]*model.Role, 0)
		}
		if len(roles) > 0 {
			body.CombineRole(roles)
		}
	}
	var count int64 = 0
	switch body.Size {
	case -1:
		documents, err = inst.mongo.Account().GroupUser().FindAll(context.Background(), query, body.Sorts)
		if err != nil {
			if err.Error() != mg.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		} else {
			count, err = inst.mongo.Account().GroupUser().Count(context.Background(), query)
			if err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}
	default:
		documents, err = inst.mongo.Account().GroupUser().Find(context.Background(), query, body.Sorts, body.Offset, body.Size)
		if err != nil {
			if err.Error() != mg.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		} else {
			count, err = inst.mongo.Account().GroupUser().Count(context.Background(), query)
			if err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}
	}
	for _, document := range documents {
		results = append(results, document.Summary())
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results, "total": count}).Go()
}

func (inst *ManagerUserHandler) searchEasmOrganization(ctx context.Context, req model.RequestCustomerOrganizationSearch, query *bson.M) error {
	if !req.IsEasm {
		return nil
	}
	docs, err := inst.mongo.Account().Roles().FindAll(ctx, &bson.M{"permissions": "view_easm"}, []string{"-_id"})
	if err != nil {
		return err
	}
	if len(docs) == 0 {
		return nil
	}
	roles := make([]string, len(docs))
	for i, doc := range docs {
		roles[i] = doc.RoleID
	}
	(*query)["role"] = bson.M{"$in": roles}
	return nil
}

func (inst *ManagerUserHandler) GetUsers(c echo.Context) error {
	req := &model.SearchUser{}
	if err := c.Bind(req); err != nil {
		inst.logger.Error("[GetUsers] bad request - data is invalid ")
		return BadRequest(c, fmt.Sprintf("data is invalid %v", err), nil)
	}
	userInfo := c.Get(defs.PP_USER_INFO_CTX).(model.PPUserInfo)
	org := userInfo.OrgId

	query := req.BuildQuery(org)
	offset, limit := req.BuildPagination()

	sorts := []string{
		"+group_role",
		"-active",
		"-created_time",
	}
	users, err := inst.mongo.Account().User().FindUsersV2(c.Request().Context(), &query, sorts, offset, limit)
	if err != nil {
		inst.logger.Errorf("failed to search users %v", err)
		return InternalServerError(c, "failed to search users")
	}
	for _, user := range users {
		twoFA := false
		if user.GroupRole.GroupRole != "admin" {
			user.GroupRole.GroupRole = "user"
		}
		for _, twoFaProperty := range user.MFaProperties {
			if twoFaProperty.Enable {
				twoFA = true
			}
		}
		user.TwoFA = twoFA
	}
	total, err := inst.mongo.Account().User().CountUsersV2(c.Request().Context(), &query)
	if err != nil {
		inst.logger.Errorf("failed to count users %v", err)
		return InternalServerError(c, "failed to count users")
	}
	response := map[string]interface{}{
		"users": users,
		"total": total,
	}
	return c.JSON(http.StatusOK, response)
}

func (inst *ManagerUserHandler) GetStatistical(c echo.Context) error {
	req := &model.SearchUserStatistic{}
	if err := c.Bind(req); err != nil {
		inst.logger.Error("[GetStatistical] bad request - data is invalid ")
		return BadRequest(c, fmt.Sprintf("data is invalid %v", err), nil)
	}
	userInfo := c.Get(defs.PP_USER_INFO_CTX).(model.PPUserInfo)
	org := userInfo.OrgId
	query := req.BuildQuery(org)

	stats, err := inst.mongo.Account().User().GetFieldStats(c.Request().Context(), &query)
	if err != nil {
		inst.logger.Error("[GetStatistical] failed to get stats")
		return InternalServerError(c, "failed to search users")
	}
	return Success(c, "get statistical success", stats)
}

func (inst *ManagerUserHandler) GetUser(c echo.Context) error {
	body, err := inst.verifyGetOrganizationUser(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	user, err := inst.mongo.Account().User().Get(context.Background(), body.Username)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusNotFound).Log(err).Go()
	}
	groupUser, err := inst.mongo.Account().GroupUser().Get(context.Background(), body.ID)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusNotFound).Log(err).Go()
	}
	if user.GroupID != groupUser.ID {
		return rest.JSON(c).Code(rest.StatusNotFound).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(user).Go()
}

func (inst *ManagerUserHandler) DeleteUser(c echo.Context) error {
	requestID := c.Param("id")
	userInfo := c.Get(defs.ContextUserCurrent).(*model.User)
	org := userInfo.GroupID
	if userInfo.ID == requestID {
		inst.logger.Errorf("Can't delete myself with delete user")
		return BadRequest(c, "Can't delete myself", nil)
	}
	// giờ nó là admin, và biết id cần xóa là thằng nào rồi -> check thằng requestID có cùng 1 tổ chức với userId này không
	userDelete, err := inst.mongo.Account().User().GetByID(context.Background(), requestID)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			inst.logger.Errorf("have err %v with find user delete", err)
			return InternalServerError(c, "not found user delete")
		}
		inst.logger.Errorf("not found user delete %v", err)
		return NotFound(c, "not found user delete")
	}
	if userDelete.GroupID != org {
		inst.logger.Errorf("Not have permission with delete user")
		return BadRequest(c, "Not have permission", nil)
	}
	// -> cung` 1 to chuc, va co quyen xoa
	err = inst.mongo.Account().User().DeleteByID(context.Background(), requestID)
	if err != nil {
		inst.logger.Errorf("have err %v with delete user", err)
		return InternalServerError(c, "Delete have error")
	}
	//Success delete
	return Success(c, "Delete User Success", nil)
}

func (inst *ManagerUserHandler) CreateUser(c echo.Context) error {
	req := &model.CreatePublicUserDTO{}
	if err := c.Bind(req); err != nil {
		log.Printf("[CreateUser] bad request - data is invalid ")
		return BadRequest(c, fmt.Sprintf("data is invalid %v", err), nil)
	}

	userInfo := c.Get(defs.ContextUserCurrent).(*model.User)
	org := userInfo.GroupID

	createUserRequest := model.CreateUserPublicDTO{
		Username:    req.Email,
		CompanyName: userInfo.CompanyName,
		StoreUserPublicDTO: model.StoreUserPublicDTO{
			Phone:      req.Phone,
			FirstName:  req.FirstName,
			LastName:   req.LastName,
			GroupID:    org,
			Language:   "vi",
			Country:    &userInfo.Country,
			TitleJob:   &userInfo.Position,
			Status:     req.Status,
			MfaEnabled: true,
		},
	}
	data, _ := json.Marshal(createUserRequest)

	createReq := httptest.NewRequest(http.MethodPost, "/hello", bytes.NewReader(data))
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := c.Echo().NewContext(createReq, rec)
	ctx.Set("user_name", "pp")

	return inst.CreatePublicUser(ctx)
}

func (inst *ManagerUserHandler) EditUser(c echo.Context) error {
	req := &model.UpdatePublicUserDTO{}
	if err := c.Bind(req); err != nil {
		inst.logger.Error("[EditUser] bad request - data is invalid ")
		return BadRequest(c, fmt.Sprintf("data is invalid %v", err), nil)
	}
	requestID := c.Param("id")
	userInfo := c.Get(defs.ContextUserCurrent).(*model.User)
	org := userInfo.GroupID
	userUpdateInfo, err := inst.mongo.Account().User().GetByID(context.Background(), requestID)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			inst.logger.Errorf("have err %v with find user update", err)
			return InternalServerError(c, "not found user update")
		}
		inst.logger.Errorf("not found user update %v", err)
		return NotFound(c, "not found user update")
	}
	if userUpdateInfo.GroupID != org {
		inst.logger.Errorf("Not have permission with edit user, khac group")
		return BadRequest(c, "Not have permission edit user", nil)
	}
	err = inst.mongo.Account().User().UpdateByID(context.Background(), requestID, req)
	if err != nil {
		inst.logger.Errorf("have err %v with update user", err)
		return InternalServerError(c, "Update have error")
	}
	return Success(c, "Update User Success", nil)
}

func (inst *ManagerUserHandler) verifyGetOrganization(c echo.Context) (body model.RequestCustomerOrganizationGet, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.ID = strings.ToLower(strings.TrimSpace(body.ID))
	if body.ID == "" {
		return body, errors.New("invalid value for parameter <id>")
	}
	// Success
	return body, nil
}

func (inst *ManagerUserHandler) verifySearchOrganization(c echo.Context) (body model.RequestCustomerOrganizationSearch, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Name
	if body.Name != "" {
		body.Name = strings.ToLower(strings.TrimSpace(body.Name))
	}
	// Type
	body.Type = strings.ToLower(strings.TrimSpace(body.Type))
	if body.Type != "" {
		if !slice.String(defs.EnumCustomerType).Contains(body.Type) {
			return body, errors.New("invalid value for parameter <type>")
		}
	} else {
		body.Type = defs.CustomerTypeAll
	}
	// Active
	if body.Active != "" {
		body.Active = strings.ToLower(body.Active)
		if _, ok := defs.MappingCustomerActive[body.Active]; !ok {
			return body, errors.New("invalid value for parameter <active>")
		}
	}
	// Roles
	if len(body.Roles) == 0 {
		body.Roles = make([]string, 0)
	}
	// Permission
	if len(body.Permissions) == 0 {
		body.Permissions = make([]string, 0)
	}
	// Sorts
	if len(body.Sorts) == 0 {
		body.Sorts = []string{"-created_time"}
	}
	// Size
	if body.Size == 0 {
		body.Size = 20
	}
	// Success
	return body, nil
}

func (inst *ManagerUserHandler) verifyGetOrganizationUser(c echo.Context) (body model.RequestOrganizationGetUser, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.ID = strings.ToLower(strings.TrimSpace(body.ID))
	if body.ID == "" {
		return body, errors.New("invalid value for parameter <id>")
	}
	body.Username = strings.ToLower(strings.TrimSpace(body.Username))
	if body.Username == "" {
		return body, errors.New("invalid value for parameter <id>")
	}
	// Success
	return body, nil
}
