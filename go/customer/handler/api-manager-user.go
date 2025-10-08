package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/service"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type MailJob struct {
	User         *model.UserV3
	Password     string
	Apikey       string
	Organization *model.Organization
	Role         *model.Role
}

type ManagerUserHandler struct {
	name     string
	logger   pencil.Logger
	mongo    mongo.GlobalRepository
	config   model.Config
	client   *resty.Client
	service  service.MailService
	mailChan chan MailJob
}

func (m *ManagerUserHandler) SetupMail(user *model.UserV3, password, apiKey string, group *model.Organization, role *model.Role) error {
	//TODO implement me
	emailData := map[string]interface{}{
		"username":         user.Username,
		"password":         password,
		"api_key":          apiKey,
		"link_change_pass": m.config.Mail.BaseURL + "/#/setting/password",
		"forgot_pass":      m.config.Mail.BaseURL + "/#/forgot",
		"link_home":        m.config.Mail.BaseURL,
		"home_page":        m.config.Mail.BaseURL,
		"created_date":     time.Unix(user.CreatedTime, 0).Format("02/01/2006"),
		"expired_date":     time.Unix(group.ExpiredTime, 0).Format("02/01/2006"),
		"phone":            m.config.Mail.PhoneContact,
		"mail":             m.config.Mail.SaleContact,
		"mail1":            m.config.Mail.SaleContact1,
		"url_login":        m.config.Mail.URLLogin,
		"language":         user.Language,
	}

	//Package name formatting
	var title, templateFile string
	switch user.Language {
	case string(defs.LanguageVietnamese):
		title = "[VCS - Threat Intelligence] - Thông báo đăng ký tài khoản thành công"
		templateFile = "user_public_created_vi.html"
		emailData["url_user_guide"] = m.config.Mail.UserGuide[string(defs.LanguageVietnamese)]
		emailData["link_condition"] = m.config.Mail.BaseURL + "/tos-vi"
		emailData["link_policy"] = m.config.Mail.BaseURL + "/privacy-vi"

		// Time range formatting
		if role.Month == 12 {
			emailData["time_range"] = "1 năm"
		} else {
			emailData["time_range"] = strconv.Itoa(role.Month) + " tháng"
		}
		emailData["package_name"] = getPackageByLang(string(defs.LanguageVietnamese), role)
		if role.Mass {
			emailData["expired_date"] = "Không giới hạn"
			emailData["time_range"] = "Không áp dụng"
		}
	default:
		title = "[VCS - Threat Intelligence] Successful Registration!"
		templateFile = "user_public_created_en.html"
		emailData["url_user_guide"] = m.config.Mail.UserGuide[string(defs.LanguageEnglish)]
		emailData["link_condition"] = m.config.Mail.BaseURL + "/tos-en"
		emailData["link_policy"] = m.config.Mail.BaseURL + "/privacy-en"

		//time range formatting
		if role.Month == 12 {
			emailData["time_range"] = "1 year"
		} else {
			suffix := " month"
			if role.Month > 1 {
				suffix = " months"
			}
			emailData["time_range"] = strconv.Itoa(role.Month) + " " + suffix
		}
		emailData["package_name"] = getPackageByLang(string(defs.LanguageEnglish), role)
		if role.Mass {
			emailData["expired_date"] = "Lifetime"
			emailData["time_range"] = "Unlimited"
		}
	}

	// Send email
	if len(m.config.Mail.ReceiverMailDev) > 0 {
		return m.service.SendWelcomeEmail(m.config.Mail.ReceiverMailDev, title, templateFile, emailData)
	}
	return m.service.SendWelcomeEmail([]string{user.Username}, title, templateFile, emailData)

}

func getPackageByLang(lang string, role *model.Role) string {
	var desc string
	data, ok := role.MultiLang[lang]
	if ok && data.Description != "" {
		desc = data.Description
	} else {
		desc = role.Description
	}
	if desc != "" {
		return desc
	}
	return role.RoleID
}

func (m *ManagerUserHandler) sendMailWorker() {
	// Create worker
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		go m.processSendMail(ctx, i)
	}
}

func (m *ManagerUserHandler) processSendMail(ctx context.Context, workerId int) {
	m.logger.Infof("waiting mail from worker %d", workerId)
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("done send mail")
			return
		case data := <-m.mailChan:
			m.logger.Infof("processing mail from worker %d, user: %s", workerId, data.User.Username)
			if err := m.SetupMail(data.User, data.Password, data.Apikey, data.Organization, data.Role); err != nil {
				m.logger.Errorf("failed send mail: %v", err)
			} else {
				m.logger.Infof("send mail password success to: %v", data.User.Username)
			}
		}
	}

}

func (m *ManagerUserHandler) GetAlertConfig(c echo.Context) error {
	userId := c.Param("id")
	if userId == "" {
		return BadRequest(c, "group_id is required", nil)
	}

	userOId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		m.logger.Errorf("failed to generated object id from id %v: %v", userId, err)
		return BadRequest(c, "bad id", nil)
	}
	user, err := m.mongo.Account().UserV3().FindByID(c.Request().Context(), userOId)
	if err != nil {
		m.logger.Errorf("failed to get user with id %v: %v", userId, err)
		return InternalServerError(c, "internal server error")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(defs.DefaultApiTimeout))
	defer cancel()

	config, err := m.service.BuildAlertConfig(ctx, user.Username, user.GroupID)
	if err != nil {
		m.logger.Errorf("failed to get alert config %v", err)
		return InternalServerError(c, "failed to get alert config")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "success",
		"data":    config,
	})
}

func (m *ManagerUserHandler) GetPositionJobs(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "success",
		"data":    defs.MAP_POSITION_JOB,
	})
}

func (m *ManagerUserHandler) GetCountries(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "success",
		"data":    defs.MAP_COUNTRY_PUBLIC,
	})
}

func (m *ManagerUserHandler) GetUserHistories(
	ctx context.Context,
	search *model.SearchUserHistory,
	sorts []bson.M,
	offset, limit int64,
) ([]*model.UserHistory, int64, error) {
	pipeline := search.BuildPipeline(offset, limit, sorts)

	// qjson, _ := json.MarshalIndent(pipeline, "", "  ")
	// fmt.Println("[DEBUG QUERY]", string(qjson))

	return m.mongo.Account().UserHistory().FindAll(ctx, pipeline)
}

func (m *ManagerUserHandler) GetUserHistoryDetail(c echo.Context) error {
	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return BadRequest(c, fmt.Sprintf("id is invalid %v", err), nil)
	}

	req := &model.SearchUserHistory{ID: &objectID}
	sorts := []bson.M{{"created_time": -1}}

	// detail chỉ cần limit = 1
	histories, total, err := m.GetUserHistories(c.Request().Context(), req, sorts, 0, 1)
	if err != nil {
		return InternalServerError(c, "failed to get user history detail")
	}
	if total == 0 {
		return NotFound(c, "History not found")
	}

	return c.JSON(http.StatusOK, histories[0])
}

func (m *ManagerUserHandler) ListUserHistory(c echo.Context) error {
	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return BadRequest(c, fmt.Sprintf("id is invalid %v", err), nil)
	}

	req := new(model.SearchUserHistory)
	if err := c.Bind(req); err != nil {
		return BadRequest(c, fmt.Sprintf("data is invalid %v", err), nil)
	}
	req.UserID = &objectID

	sorts := []bson.M{{"created_time": -1}}
	offset, limit := req.BuildPagination()

	histories, total, err := m.GetUserHistories(c.Request().Context(), req, sorts, offset, limit)
	if err != nil {
		m.logger.Errorf("failed get history: %v", err)
		return InternalServerError(c, "internal server")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"total":     total,
		"histories": histories,
	})
}

func (m *ManagerUserHandler) UpdatePublicUser(c echo.Context) error {
	var req model.UpdateUserPublicDTO
	if err := c.Bind(&req); err != nil {
		m.logger.Errorf("failed bind data: %v", err)
		return BadRequest(c, fmt.Sprintf("data is invalid %v", err), nil)
	}
	if err := c.Validate(req); err != nil {
		m.logger.Errorf("invalid request: %v", err)
		return ValidationError(c, err)
	}
	oid, err := primitive.ObjectIDFromHex(req.ID)
	if err != nil {
		m.logger.Errorf("invalid id: %v", err)
		return BadRequest(c, "invalid id", nil)
	}

	// Check user tồn tại
	detailReq := model.GetUserDetailV3{
		ID: oid,
	}
	currentUser, err := m.mongo.Account().UserV3().Detail(c.Request().Context(), detailReq.BuildPipeline())
	if err != nil {
		m.logger.Errorf("failed to get user: %v", err)
		return InternalServerError(c, "failed to get user")
	}
	if currentUser == nil {
		m.logger.Errorf("user with id not found: %s", req.ID)
		return NotFound(c, "User not found")
	}
	existingUser := &currentUser.UserV3

	// LƯU TRẠNG THÁI TRƯỚC KHI UPDATE
	userBefore := *currentUser // Tạo bản copy của user hiện tại
	oldOrg := userBefore.GroupID
	originalJson, _ := json.Marshal(userBefore)
	org, role, err := m.genUserData(c.Request().Context(), req.StoreUserPublicDTO, existingUser)
	if err != nil {
		m.logger.Errorf("[UpdatePublicUser] failed gen user: %v", err)
		return BadRequest(c, err.Error(), nil)
	}
	// If change org, check quota new org
	if oldOrg != req.GroupID && role.LimitAccount != -1 {
		userCount, err := m.mongo.Account().UserV3().CountByGroupID(c.Request().Context(), req.GroupID)
		if err != nil {
			m.logger.Errorf("failed to count users in organization %v", err)
			return InternalServerError(c, "failed to count users in organization")
		}
		if userCount >= int64(role.LimitAccount) {
			m.logger.Error("[CreatePublicUser] user limit exceeded for organization")
			return BadRequest(c, "User limit exceeded for organization", nil)
		}
	}

	// enable mfa
	if currentUser.MfaEnabled && !req.MfaEnabled {
		mfaProperties := existingUser.MfaProperties
		for i := range mfaProperties {
			existingUser.MfaProperties[i].Enable = false
		}
		currentUser.MfaEnabled = false
	}
	currentUser.UserV3 = *existingUser
	// History with before/after comparison

	updatedJson, _ := json.Marshal(currentUser)
	diff, err := utils.GetChangedFieldsJson(originalJson, updatedJson, defs.UserCompKeys)
	if err != nil {
		m.logger.Errorf("failed to get changed fields between %+v and %+v: %v", userBefore, existingUser, err)
		return InternalServerError(c, "failed to get change fields")
	}
	if len(diff) == 0 {
		return Success(c, "No changes detected", nil)
	}

	updateField := bson.M{
		"group_id":             existingUser.GroupID,
		"first_name":           existingUser.FirstName,
		"last_name":            existingUser.LastName,
		"phone":                existingUser.Phone,
		"country":              existingUser.Country,
		"language":             existingUser.Language,
		"position":             existingUser.Position,
		"active":               existingUser.Active,
		"updated_time":         existingUser.UpdatedTime,
		"ownership":            existingUser.Ownership,
		"mfa_properties":       existingUser.MfaProperties,
		"role":                 existingUser.Role,
		"ancestors":            existingUser.Ancestors,
		"api_key":              existingUser.APIKey,
		"api_key_expired_time": existingUser.APIKeyExpiredTime,
		"api_key_updated_time": existingUser.APIKeyUpdatedTime,
	}

	// Save
	if err := m.mongo.Account().UserV3().Update(c.Request().Context(), oid, updateField); err != nil {
		m.logger.Errorf("failed update user: %v", err)
		return InternalServerError(c, "failed to update user")
	}
	beforeChange := make(map[string]any)
	afterChange := make(map[string]any)
	for k, r := range diff {
		beforeChange[k] = r.Before
		afterChange[k] = r.After
		if k == "group_id" {
			beforeChange[k] = currentUser.GroupUserTenantId
			afterChange[k] = org.TenantId
		}
	}
	if err := m.createUserHistory(c.Request().Context(), model.CreateUserHistoryDTO{
		UserID:  existingUser.ID,
		Creator: c.Get("user_name").(string),
		Before:  beforeChange,
		After:   afterChange,
		Event:   defs.HistoryEventUpdate,
	}); err != nil {
		m.logger.Errorf("[UpdatePublicUser] failed create user history: %v", err)
	}

	return Success(c, "User updated successfully", nil)
}

func getOwnership(val bool, isRoleMass bool) bool {
	if !isRoleMass {
		return val
	}
	return false
}

func (m *ManagerUserHandler) genApiKey(isActive bool, role *model.Role, org *model.Organization) (model.UserV3, error) {
	var user model.UserV3
	if isActive && m.mongo.Account().Roles().HasPermission(role, defs.PermissionPremium) {
		apiKey, _ := utils.GenID("api_key") // never returns an error unless passing in wrong resourceType
		user.APIKey = apiKey
		user.APIKeyUpdatedTime = time.Now().Unix()
		user.APIKeyExpiredTime = org.ExpiredTime
	}
	return user, nil
}

func (m *ManagerUserHandler) genUserData(ctx context.Context, req model.StoreUserPublicDTO, user *model.UserV3) (*model.Organization, *model.Role, error) {
	org, err := m.mongo.Account().GroupUser().GetOrg(ctx, req.GroupID, nil)
	if err != nil {
		m.logger.Errorf("failed find organization: %v", err)
		return nil, nil, fmt.Errorf("organization not found")
	}

	role, err := m.mongo.Account().Roles().GetByName(ctx, org.Role)
	if err != nil {
		m.logger.Errorf("failed find role: %v", err)
		return nil, nil, fmt.Errorf("package not found")
	}
	user.FirstName = req.FirstName
	user.LastName = req.LastName
	user.GroupID = org.Id
	user.Position = req.TitleJob
	user.Country = req.Country
	user.Phone = req.Phone
	user.Language = req.Language
	user.Active = req.Status
	user.Ownership = getOwnership(req.DomainOwnership, role.Mass)
	user.UpdatedTime = time.Now().Unix()

	userApiKey, err := m.genApiKey(req.Status, role, org)
	if err != nil {
		m.logger.Errorf("failed gen api key: %v", err)
		return nil, nil, fmt.Errorf("failed gen api key")
	}
	user.APIKey = userApiKey.APIKey
	user.APIKeyUpdatedTime = userApiKey.APIKeyUpdatedTime
	user.APIKeyExpiredTime = userApiKey.APIKeyExpiredTime
	user.Role = org.Role
	user.Ancestors = org.Ancestors
	user.CompanyName = org.Name

	return org, role, nil
}

func (m *ManagerUserHandler) DeletePublicUser(c echo.Context) error {
	//TODO implement me
	id := c.Param("id")
	if id == "" {
		m.logger.Error("[DeletePublicUser] bad request - id is required ")
		return BadRequest(c, "id is required", nil)
	}

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		m.logger.Error("[DeletePublicUser] invalid ObjectID format")
		return BadRequest(c, "invalid user ID format", nil)
	}

	err = m.mongo.Account().UserV3().DeleteByID(c.Request().Context(), objID)
	if err != nil {
		m.logger.Errorf("failed to delete user %v", err)
		return InternalServerError(c, "failed to delete user")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "User deleted successfully",
	})

}

func (m *ManagerUserHandler) CreatePublicUser(c echo.Context) error {
	//TODO implement me
	var req model.CreateUserPublicDTO
	if err := c.Bind(&req); err != nil {
		m.logger.Errorf("[CreatePublicUser] bad request - data is invalid, %v", err)
		return BadRequest(c, fmt.Sprintf("data is invalid %v", err), nil)
	}

	if err := c.Validate(req); err != nil {
		m.logger.Errorf("[CreatePublicUser] validation error, %v", err)
		return ValidationError(c, err)
	}
	now := time.Now().Unix()
	creator := c.Get("user_name").(string)
	// Check if user already exists
	existingUser, err := m.mongo.Account().UserV3().FindByUserName(c.Request().Context(), req.Username)
	if err != nil {
		m.logger.Errorf("failed to check existing user %v", err)
		return InternalServerError(c, "failed to check existing user")
	}
	if existingUser != nil {
		m.logger.Errorf("[CreatePublicUser] user %s already exists", req.Username)
		return BadRequest(c, "User already exists", nil)
	}
	newUser := &model.UserV3{
		Username:                 req.Username,
		Creator:                  creator,
		CreatedTime:              now,
		ActionConfirmEmailTime:   1,
		ActionConfirmEmailStatus: 1,
		MfaProperties:            make([]model.MfaProperty, 0),
	}
	organization, role, err := m.genUserData(c.Request().Context(), req.StoreUserPublicDTO, newUser)
	if err != nil {
		m.logger.Errorf("[CreatePublicUser] failed gen user: %v", err)
		return BadRequest(c, err.Error(), nil)
	}
	if req.CompanyName != "" {
		newUser.CompanyName = req.CompanyName
	}
	if req.TermAccept != nil {
		newUser.TermAccept = *req.TermAccept
	}
	if role.LimitAccount != -1 {
		userCount, err := m.mongo.Account().UserV3().CountByGroupID(c.Request().Context(), organization.Id)
		if err != nil {
			m.logger.Errorf("failed to count users in organization %v", err)
			return InternalServerError(c, "failed to count users in organization")
		}
		if userCount >= int64(role.LimitAccount) {
			m.logger.Error("[CreatePublicUser] user limit exceeded for organization")
			return BadRequest(c, "User limit exceeded for organization", nil)
		}
	}

	password := utils.GeneratePassword()
	// m.logger.Infof("gen password: %s for user :%s", password, req.Username)
	hashedPassword := utils.GeneratePasswordHash(password, "pbkdf2:sha256:50000", 8)
	newUser.Password = hashedPassword

	confirmEmailCode, err := utils.GenConfirmMail("confirm_email")
	if err != nil {
		m.logger.Errorf("failed to generate confirm email code %v", err)
		return BadRequest(c, "failed generate email code", nil)
	}
	newUser.ActionConfirmEmailCode = confirmEmailCode
	if m.config.App.Mode == "dev" {
		newUser.MfaInit = true
	}

	if err := m.mongo.Account().UserV3().Create(c.Request().Context(), newUser); err != nil {
		m.logger.Errorf("failed to create new user %v", err)
		return InternalServerError(c, "failed to create new user")
	}

	// Gửi email thông báo
	if newUser.Active {
		m.mailChan <- MailJob{
			User:         newUser,
			Password:     password,
			Apikey:       newUser.APIKey,
			Organization: organization,
			Role:         role,
		}
	}
	if err := m.createUserHistory(c.Request().Context(), model.CreateUserHistoryDTO{
		UserID:  newUser.ID,
		Creator: creator,
		Event:   defs.HistoryEventCreate,
	}); err != nil {
		m.logger.Errorf("[CreatePublicUser] failed create user history: %v", err)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":  "User created successfully",
		"username": newUser.Username,
		"id":       newUser.ID,
	})

}

func (m *ManagerUserHandler) Detail(c echo.Context) error {
	//TODO implement me
	id := c.Param("id")

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		m.logger.Error("[Detail] bad request - id is invalid ")
		return BadRequest(c, fmt.Sprintf("id is invalid %v", err), nil)
	}

	req := &model.GetUserDetailV3{
		ID: objectID,
	}

	pipeline := req.BuildPipeline()
	qjson, _ := json.MarshalIndent(pipeline, "", "  ")
	fmt.Println("[DEBUG QUERY]", string(qjson))

	user, err := m.mongo.Account().UserV3().Detail(c.Request().Context(), pipeline)
	if err != nil {
		m.logger.Errorf("failed to get user detail %v", err)
		return InternalServerError(c, "failed to get user detail")
	}

	return c.JSON(http.StatusOK, user)
}

func (m *ManagerUserHandler) ChangeStatus(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		m.logger.Error("[ChangeStatus] bad request - id is required ")
		return BadRequest(c, "id is required", nil)
	}

	req := new(model.ChangeStatusUserDTO)
	if err := c.Bind(req); err != nil {
		m.logger.Error("[ChangeStatus] bad request - data is invalid ")
		return BadRequest(c, fmt.Sprintf("data is invalid %v", err), nil)
	}

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		m.logger.Error("[ChangeStatus] invalid ObjectID format")
		return BadRequest(c, "invalid user ID format", nil)
	}

	currentUser, err := m.mongo.Account().UserV3().FindByID(c.Request().Context(), objID)
	if err != nil {
		m.logger.Errorf("failed to get current user status %v", err)
		return InternalServerError(c, "failed to get current user")
	}

	newStatus := bool(req.Status)
	if currentUser.Active == newStatus {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": fmt.Sprintf("User status is already %v", newStatus),
		})
	}

	// Cập nhật và tạo lịch sử chỉ khi có thay đổi
	updatedBy := c.Get("user_name").(string)
	_, _, err = m.genUserData(c.Request().Context(), model.StoreUserPublicDTO{
		Status:  bool(req.Status),
		GroupID: currentUser.GroupID,
	}, currentUser)
	if err != nil {
		m.logger.Errorf("failed gen user data: %v", err)
		return InternalServerError(c, "failed to update user status")
	}

	updateField := bson.M{
		"api_key":              currentUser.APIKey,
		"api_key_expired_time": currentUser.APIKeyExpiredTime,
		"api_key_updated_time": currentUser.APIKeyUpdatedTime,
		"active":               currentUser.Active,
	}

	if err := m.mongo.Account().UserV3().Update(c.Request().Context(), objID, updateField); err != nil {
		m.logger.Errorf("failed update user status: %v", err)
		return InternalServerError(c, "failed to update user status")
	}
	event := defs.HistoryEventChangeActiveStatus
	if !newStatus {
		event = defs.HistoryEventChangeInactiveStatus
	}
	if err := m.createUserHistory(c.Request().Context(), model.CreateUserHistoryDTO{
		UserID:  objID,
		Creator: updatedBy,
		Before: map[string]any{
			"status": currentUser.Active,
		},
		After: map[string]any{
			"status": newStatus,
		},
		Event: event,
	}); err != nil {
		m.logger.Errorf("failed create user history: %v", err)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Change status user successfully",
	})
}

func (m *ManagerUserHandler) createUserHistory(ctx context.Context, req model.CreateUserHistoryDTO) error {
	actions := make([]string, 0)
	var jsonBefore, jsonAfer []byte
	if req.Before != nil {
		for k := range req.Before {
			actions = append(actions, k)
		}
		jsonBefore, _ = json.Marshal(req.Before)
		jsonAfer, _ = json.Marshal(req.After)
	}

	history := &model.UserHistory{
		UserID:      req.UserID,
		Creator:     req.Creator,
		Event:       req.Event,
		CreatedTime: time.Now().Unix(),
		UserBefore:  string(jsonBefore),
		UserAfter:   string(jsonAfer),
		Action:      strings.Join(actions, ", "),
	}
	if err := m.mongo.Account().UserHistory().Create(ctx, history); err != nil {
		return err
	}
	return nil
}

func (m *ManagerUserHandler) List(c echo.Context) error {
	//TODO implement me
	req := new(model.SearchUserV3)
	if err := c.Bind(req); err != nil {
		m.logger.Error("[List] bad request - data is invalid ")
		return BadRequest(c, fmt.Sprintf("data is invalid %v", err), nil)
	}

	sorts := []bson.M{{"created_time": -1}}
	offset, limit := req.BuildPagination()
	pipeline := req.BuildPipeline(offset, limit, sorts)

	// qjson, _ := json.MarshalIndent(pipeline, "", "  ")
	// fmt.Println("[DEBUG QUERY]", string(qjson))

	users, total, err := m.mongo.Account().UserV3().FindUserV3(c.Request().Context(), pipeline)
	if err != nil {
		m.logger.Errorf("failed to search users %v", err)
		return InternalServerError(c, "failed to search users")
	}

	response := map[string]interface{}{
		"total": total,
		"data":  users,
	}
	return c.JSON(http.StatusOK, response)
}

func (m *ManagerUserHandler) StatisticV3(c echo.Context) error {
	//TODO implement me
	req := new(model.SearchUserV3StatisticRequest)
	if err := c.Bind(req); err != nil {
		m.logger.Error("[List] bad request - data is invalid ")
		return BadRequest(c, fmt.Sprintf("data is invalid %v", err), nil)
	}

	pipeline := req.BuildPipeline()
	// qjson, _ := json.MarshalIndent(pipeline, "", "  ")
	// fmt.Println("[DEBUG QUERY]", string(qjson))

	results, err := m.mongo.Account().UserV3().StatisticV3(c.Request().Context(), pipeline)
	if err != nil {
		m.logger.Errorf("failed to search users %v", err)
		return InternalServerError(c, "failed to search users")
	}

	response := map[string]interface{}{
		"data": results,
	}
	return c.JSON(http.StatusOK, response)
}

func NewManagerUserHandler(conf model.Config) ManagerUserHandlerInterface {
	handler := &ManagerUserHandler{name: defs.HandlerManagerUser, config: conf}
	handler.logger, _ = pencil.New(handler.name, pencil.DebugLevel, true, os.Stdout)
	handler.mongo = mongo.NewGlobalRepository(conf.Adapter.Mongo)
	handler.client = resty.New().SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).SetTimeout(time.Duration(defs.DefaultApiTimeout))
	handler.service = service.NewAlertService(handler.mongo.Account().UserSetting(), handler.mongo.Settings().Schedule(), handler.mongo.Account(),
		&conf.Mail, conf.Mail.TemplatePath)
	handler.mailChan = make(chan MailJob, 10)
	handler.sendMailWorker()
	return handler
}
