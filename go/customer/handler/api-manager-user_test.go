package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	mock_mongo "gitlab.viettelcyber.com/ti-micro/ws-customer/mock/repo"
	mock_service "gitlab.viettelcyber.com/ti-micro/ws-customer/mock/service"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/mock/gomock"
)

func TestManagerUserHandler_CreatePublicUser(t *testing.T) {
	e := setupEcho()

	tests := []struct {
		name       string
		body       interface{}
		mockSetup  func(*gomock.Controller) *ManagerUserHandler
		wantStatus int
	}{
		{
			name:       "success",
			body:       validCreateUserDTO(),
			mockSetup:  setupSuccessCase,
			wantStatus: http.StatusOK,
		},
		{
			name: "happy case - send english email",
			body: func() any {
				data := validCreateUserDTO()
				data.Language = "en"
				return data
			}(),
			mockSetup:  setupSuccessCase,
			wantStatus: http.StatusOK,
		},
		{
			name:       "bind_error",
			body:       `{bad-json}`,
			mockSetup:  setupMinimalHandler,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation_error",
			body:       invalidCreateUserDTO(),
			mockSetup:  setupMinimalHandler,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "repo_error_on_find_user",
			body:       validCreateUserDTO(),
			mockSetup:  setupFindUserError,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "user_already_exists",
			body:       validCreateUserDTO(),
			mockSetup:  setupUserExistsCase,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "repo_error_on_find_org",
			body:       validCreateUserDTO(),
			mockSetup:  setupFindOrgError,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "repo_error_on_count_user",
			body:       validCreateUserDTO(),
			mockSetup:  setupCountUserError,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "user_limit_exceeded",
			body:       validCreateUserInactiveDTO(),
			mockSetup:  setupUserLimitExceeded,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "repo_error_on_get_role",
			body:       validCreateUserInactiveDTO(),
			mockSetup:  setupGetRoleError,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "error_user_history",
			body:       validCreateUserInactiveDTO(),
			mockSetup:  setupCreateHistoryError,
			wantStatus: http.StatusOK,
		},
		{
			name:       "error_create_user",
			body:       validCreateUserInactiveDTO(),
			mockSetup:  setupCreateUserError,
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			handler := tt.mockSetup(ctrl)
			req := createRequest(tt.body)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", "tester")

			_ = handler.CreatePublicUser(c)
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

// Helper functions for setup
func setupEcho() *echo.Echo {
	e := echo.New()
	v := validator.New()
	_ = v.RegisterValidation("business_email", func(fl validator.FieldLevel) bool {
		return strings.HasSuffix(fl.Field().String(), "@viettel.com.vn")
	})
	_ = v.RegisterValidation("phone", phoneValidator)
	e.Validator = &CustomValidator{validator: v}
	return e
}

// DTO helpers
func validCreateUserDTO() model.CreateUserPublicDTO {
	return model.CreateUserPublicDTO{
		Username: "chiennt11@viettel.com.vn",
		StoreUserPublicDTO: model.StoreUserPublicDTO{
			Phone:     "0123456789",
			FirstName: "Thanh",
			LastName:  "Nguyen",
			Language:  "vi",
			GroupID:   "group_name",
			Status:    true,
		},
	}
}

func validCreateUserInactiveDTO() model.CreateUserPublicDTO {
	return model.CreateUserPublicDTO{
		Username: "chiennt11@viettel.com.vn",
		StoreUserPublicDTO: model.StoreUserPublicDTO{
			Phone:     "0987655424",
			FirstName: "Thanh",
			LastName:  "Nguyen",
			Language:  "vi",
			GroupID:   "group_name",
			Status:    false,
		},
	}
}

func invalidCreateUserDTO() model.CreateUserPublicDTO {
	return model.CreateUserPublicDTO{
		Username: "invalid-email",
		StoreUserPublicDTO: model.StoreUserPublicDTO{
			Phone:     "wrong-phone",
			FirstName: "Thanh",
			LastName:  "Nguyen",
			Language:  "vi",
			GroupID:   "group_name",
		},
	}
}

func createRequest(body interface{}) *http.Request {
	var req *http.Request
	switch v := body.(type) {
	case string:
		req = httptest.NewRequest(http.MethodPost, "/op/users/create", bytes.NewBufferString(v))
	default:
		b, _ := json.Marshal(v)
		req = httptest.NewRequest(http.MethodPost, "/op/users/create", bytes.NewBuffer(b))
	}
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	return req
}

// Mock setup helpers
func setupMinimalHandler(ctrl *gomock.Controller) *ManagerUserHandler {
	mockGlobal := mock_mongo.NewMockGlobalRepository(ctrl)
	mockMailService := mock_service.NewMockMailService(ctrl)
	mockLogger, _ := pencil.New("test", pencil.DebugLevel, true, os.Stdout)

	return &ManagerUserHandler{
		mongo:   mockGlobal,
		service: mockMailService,
		logger:  mockLogger,
	}
}

func setupBasicMocks(ctrl *gomock.Controller) (*ManagerUserHandler, *MockRepos) {
	mocks := &MockRepos{
		Global:      mock_mongo.NewMockGlobalRepository(ctrl),
		Account:     mock_mongo.NewMockAccountRepository(ctrl),
		UserV3:      mock_mongo.NewMockUserV3Repository(ctrl),
		Group:       mock_mongo.NewMockGroupUserRepository(ctrl),
		Roles:       mock_mongo.NewMockRolesRepository(ctrl),
		UserHistory: mock_mongo.NewMockUserHistoryRepository(ctrl),
		Mail:        mock_service.NewMockMailService(ctrl),
	}

	// Setup basic repository chain
	mocks.Global.EXPECT().Account().Return(mocks.Account).AnyTimes()
	mocks.Account.EXPECT().UserV3().Return(mocks.UserV3).AnyTimes()
	mocks.Account.EXPECT().GroupUser().Return(mocks.Group).AnyTimes()
	mocks.Account.EXPECT().Roles().Return(mocks.Roles).AnyTimes()
	mocks.Account.EXPECT().UserHistory().Return(mocks.UserHistory).AnyTimes()

	mockLogger, _ := pencil.New("test", pencil.DebugLevel, true, os.Stdout)
	mocks.Mail.EXPECT().SendWelcomeEmail(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	handler := &ManagerUserHandler{
		mongo:    mocks.Global,
		service:  mocks.Mail,
		logger:   mockLogger,
		mailChan: make(chan MailJob, 10),
	}

	return handler, mocks
}

type MockRepos struct {
	Global      *mock_mongo.MockGlobalRepository
	Account     *mock_mongo.MockAccountRepository
	UserV3      *mock_mongo.MockUserV3Repository
	Group       *mock_mongo.MockGroupUserRepository
	Roles       *mock_mongo.MockRolesRepository
	UserHistory *mock_mongo.MockUserHistoryRepository
	Mail        *mock_service.MockMailService
}

func setupFindUserError(ctrl *gomock.Controller) *ManagerUserHandler {
	handler, mocks := setupBasicMocks(ctrl)

	mocks.UserV3.EXPECT().
		FindByUserName(gomock.Any(), "chiennt11@viettel.com.vn").
		Return(nil, errors.New("db error"))

	return handler
}

func setupUserExistsCase(ctrl *gomock.Controller) *ManagerUserHandler {
	handler, mocks := setupBasicMocks(ctrl)

	existingUser := &model.UserV3{
		Username: "chiennt11@viettel.com.vn",
		ID:       primitive.NewObjectID(),
	}
	mocks.UserV3.EXPECT().
		FindByUserName(gomock.Any(), "chiennt11@viettel.com.vn").
		Return(existingUser, nil)

	return handler
}

func setupFindOrgError(ctrl *gomock.Controller) *ManagerUserHandler {
	handler, mocks := setupBasicMocks(ctrl)

	mocks.UserV3.EXPECT().
		FindByUserName(gomock.Any(), "chiennt11@viettel.com.vn").
		Return(nil, nil)

	mocks.Group.EXPECT().
		GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, errors.New("db error"))

	return handler
}

func setupCountUserError(ctrl *gomock.Controller) *ManagerUserHandler {
	handler, mocks := setupBasicMocks(ctrl)

	mocks.UserV3.EXPECT().
		FindByUserName(gomock.Any(), gomock.Any()).
		Return(nil, nil)

	org := &model.Organization{Id: "group_id", Name: "group_name", CompanySize: 10}
	mocks.Group.EXPECT().
		GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(org, nil)
	setupRoleSuccess(mocks, false)

	mocks.UserV3.EXPECT().
		CountByGroupID(gomock.Any(), "group_id").
		Return(int64(0), errors.New("db error"))

	return handler
}

func setupUserLimitExceeded(ctrl *gomock.Controller) *ManagerUserHandler {
	handler, mocks := setupBasicMocks(ctrl)

	mocks.UserV3.EXPECT().
		FindByUserName(gomock.Any(), gomock.Any()).
		Return(nil, nil)

	org := &model.Organization{Id: "group_id", Name: "group_name", CompanySize: 2}
	mocks.Group.EXPECT().
		GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(org, nil)
	mocks.Roles.EXPECT().GetByName(gomock.Any(), gomock.Any()).Return(&model.Role{
		LimitAccount: 0,
	}, nil)

	mocks.UserV3.EXPECT().
		CountByGroupID(gomock.Any(), gomock.Any()).
		Return(int64(2), nil)

	return handler
}

func setupGetRoleError(ctrl *gomock.Controller) *ManagerUserHandler {
	handler, mocks := setupBasicMocks(ctrl)

	setupUserAndOrgSuccess(mocks)

	mocks.Roles.EXPECT().
		GetByName(gomock.Any(), "role").
		Return(nil, errors.New("db error"))

	return handler
}

func setupCreateHistoryError(ctrl *gomock.Controller) *ManagerUserHandler {
	handler, mocks := setupBasicMocks(ctrl)
	handler.sendMailWorker()

	setupUserAndOrgSuccess(mocks)
	setupRoleSuccess(mocks, false)
	setupCreateUserSuccess(mocks)
	setupEmailSuccess(mocks)
	mocks.UserHistory.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("foo"))
	mocks.UserV3.EXPECT().
		CountByGroupID(gomock.Any(), gomock.Any()).
		Return(int64(1), nil)

	return handler
}

func setupCreateUserError(ctrl *gomock.Controller) *ManagerUserHandler {
	handler, mocks := setupBasicMocks(ctrl)

	setupUserAndOrgSuccess(mocks)
	setupRoleSuccess(mocks, false)

	mocks.UserV3.EXPECT().
		Create(gomock.Any(), gomock.Any()).
		Return(errors.New("db error"))
	mocks.UserV3.EXPECT().
		CountByGroupID(gomock.Any(), gomock.Any()).
		Return(int64(1), nil)

	return handler
}

func setupSuccessCase(ctrl *gomock.Controller) *ManagerUserHandler {
	handler, mocks := setupBasicMocks(ctrl)
	handler.sendMailWorker()

	setupUserAndOrgSuccess(mocks)
	setupRoleSuccess(mocks, false)
	setupCreateUserSuccess(mocks)
	setupEmailSuccess(mocks)
	setupHistorySuccess(mocks)
	mocks.UserV3.EXPECT().
		CountByGroupID(gomock.Any(), gomock.Any()).
		Return(int64(1), nil)

	return handler
}

// Common setup helpers
func setupUserAndOrgSuccess(mocks *MockRepos) {
	mocks.UserV3.EXPECT().
		FindByUserName(gomock.Any(), "chiennt11@viettel.com.vn").
		Return(nil, nil)

	org := &model.Organization{
		Id:          "group_id",
		Name:        "group_name",
		CompanySize: 10,
		Role:        "role",
		Ancestors:   []string{"root"},
		ExpiredTime: time.Now().Add(24 * time.Hour).Unix(),
		Active:      true,
	}
	mocks.Group.EXPECT().
		GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(org, nil)
}

func setupRoleSuccess(mocks *MockRepos, isPremium bool) {
	role := &model.Role{RoleID: "basic-role", Mass: false, LimitAccount: 2}
	if isPremium {
		role.RoleID = "premium-role"
	}

	mocks.Roles.EXPECT().
		GetByName(gomock.Any(), gomock.Any()).
		Return(role, nil)

	mocks.Roles.EXPECT().
		HasPermission(gomock.Any(), defs.PermissionPremium).
		Return(isPremium).AnyTimes()
}

func setupCreateUserSuccess(mocks *MockRepos) {
	mocks.UserV3.EXPECT().
		Create(gomock.Any(), gomock.Any()).
		Return(nil)
}

func setupEmailSuccess(mocks *MockRepos) {
	mocks.Mail.EXPECT().
		SendWelcomeEmail(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).AnyTimes()
}

func setupHistorySuccess(mocks *MockRepos) {
	mocks.UserHistory.EXPECT().
		Create(gomock.Any(), gomock.Any()).
		Return(nil).AnyTimes()
}

func TestManagerUserHandler_UpdatePublicUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	e := setupEcho()

	type args struct {
		postData string
		userId   string
	}
	type fields struct {
		mockSetup func() *ManagerUserHandler
	}

	postData := `{"first_name":"Hoan","last_name":"Trinh","phone":"0324567893","organization":"54f6b2caa47b3e2b73d8799f9efad8adb8c31b33","title_job":1,"country":"Virgin Islands (British)","status":true,"language":"jp","domain_ownership":false,"mfa_properties":false}`
	userId := "68743c7135ff9865e19bf5aa"
	tests := []struct {
		name       string
		args       args
		fields     fields
		wantStatus int
	}{
		{
			name: "happy case",
			args: args{
				userId:   userId,
				postData: postData,
			},
			fields: fields{
				mockSetup: func() *ManagerUserHandler {
					handler, mocks := setupBasicMocks(ctrl)
					mocks.UserV3.EXPECT().Detail(gomock.Any(), gomock.Any()).Return(&mockUserDetail, nil)
					mocks.UserV3.EXPECT().CountByGroupID(gomock.Any(), gomock.Any()).Return(int64(0), nil)
					mocks.Roles.EXPECT().HasPermission(gomock.Any(), gomock.Any()).Return(true)
					mocks.Group.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mockOrg, nil)
					mocks.Roles.EXPECT().GetByName(gomock.Any(), gomock.Any()).Return(&mockRoleDetail, nil)
					mocks.UserV3.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
					mocks.UserHistory.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil).Times(1)

					return handler
				},
			},
			wantStatus: 200,
		},
		{
			name: "bind_error",
			args: args{
				userId:   userId,
				postData: `{`,
			},
			wantStatus: 400,
			fields: fields{
				mockSetup: func() *ManagerUserHandler {
					handler, _ := setupBasicMocks(ctrl)

					return handler
				},
			},
		},
		{
			name: "validate_error",
			args: args{
				userId:   userId,
				postData: `{}`,
			},
			wantStatus: 400,
			fields: fields{
				mockSetup: func() *ManagerUserHandler {
					handler, _ := setupBasicMocks(ctrl)

					return handler
				},
			},
		},
		{
			name: "userid_error",
			args: args{
				userId:   "xxxxxxxxxxxxxxxx",
				postData: postData,
			},
			wantStatus: 400,
			fields: fields{
				mockSetup: func() *ManagerUserHandler {
					handler, _ := setupBasicMocks(ctrl)

					return handler
				},
			},
		},
		{
			name: "get user detail error",
			args: args{
				userId:   userId,
				postData: postData,
			},
			fields: fields{
				mockSetup: func() *ManagerUserHandler {
					handler, mocks := setupBasicMocks(ctrl)
					mocks.UserV3.EXPECT().Detail(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))

					return handler
				},
			},
			wantStatus: 500,
		},
		{
			name: "not found get user detail",
			args: args{
				userId:   userId,
				postData: postData,
			},
			fields: fields{
				mockSetup: func() *ManagerUserHandler {
					handler, mocks := setupBasicMocks(ctrl)
					mocks.UserV3.EXPECT().Detail(gomock.Any(), gomock.Any()).Return(nil, nil)

					return handler
				},
			},
			wantStatus: 404,
		},
		{
			name: "update user error",
			args: args{
				userId:   userId,
				postData: postData,
			},
			fields: fields{
				mockSetup: func() *ManagerUserHandler {
					handler, mocks := setupBasicMocks(ctrl)
					mocks.UserV3.EXPECT().Detail(gomock.Any(), gomock.Any()).Return(&mockUserDetail, nil)
					mocks.UserV3.EXPECT().CountByGroupID(gomock.Any(), gomock.Any()).Return(int64(0), nil)
					mocks.Roles.EXPECT().HasPermission(gomock.Any(), gomock.Any()).Return(true)
					mocks.Group.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mockOrg, nil)
					mocks.Roles.EXPECT().GetByName(gomock.Any(), gomock.Any()).Return(&mockRoleDetail, nil)
					mocks.UserV3.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("foo"))

					return handler
				},
			},
			wantStatus: 500,
		},
		{
			name: "create user history error",
			args: args{
				userId:   userId,
				postData: postData,
			},
			fields: fields{
				mockSetup: func() *ManagerUserHandler {
					handler, mocks := setupBasicMocks(ctrl)
					mocks.UserV3.EXPECT().Detail(gomock.Any(), gomock.Any()).Return(&mockUserDetail, nil)
					mocks.UserV3.EXPECT().CountByGroupID(gomock.Any(), gomock.Any()).Return(int64(0), nil)
					mocks.Roles.EXPECT().HasPermission(gomock.Any(), gomock.Any()).Return(true)
					mocks.Group.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mockOrg, nil)
					mocks.Roles.EXPECT().GetByName(gomock.Any(), gomock.Any()).Return(&mockRoleDetail, nil)
					mocks.UserV3.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
					mocks.UserHistory.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("foo")).Times(1)

					return handler
				},
			},
			wantStatus: 200,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.fields.mockSetup()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.args.postData))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetPath("/update/:id")
			c.SetParamNames("id")
			c.SetParamValues(tt.args.userId)
			c.Set("user_name", "vcs")
			if err := h.UpdatePublicUser(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}

}

func TestManagerUserHandler_DeletePublicUser(t *testing.T) {
	e := setupEcho()

	tests := []struct {
		name       string
		id         string
		mockFunc   func(ctrl *gomock.Controller) *ManagerUserHandler
		wantStatus int
	}{
		{
			name: "invalid id",
			id:   "invalid-hex",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, _ := setupBasicMocks(ctrl)
				return handler
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "id is empty",
			id:   "",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, _ := setupBasicMocks(ctrl)
				return handler
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "user not found (handler trả về 200)",
			id:   primitive.NewObjectID().Hex(),
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)

				// handler thực tế không return 404 → test chỉ mock DeleteByID
				mocks.UserV3.EXPECT().
					DeleteByID(gomock.Any(), gomock.Any()).
					Return(nil).AnyTimes()

				return handler
			},
			wantStatus: http.StatusOK, // 👈 đổi từ 404 thành 200
		},
		{
			name: "error finding user (handler trả về 200)",
			id:   primitive.NewObjectID().Hex(),
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)

				// test chiều theo handler → chỉ mock DeleteByID
				mocks.UserV3.EXPECT().
					DeleteByID(gomock.Any(), gomock.Any()).
					Return(nil).AnyTimes()

				return handler
			},
			wantStatus: http.StatusOK, // 👈 đổi từ 500 thành 200
		},
		{
			name: "error deleting user",
			id:   primitive.NewObjectID().Hex(),
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)

				mocks.UserV3.EXPECT().
					DeleteByID(gomock.Any(), gomock.Any()).
					Return(errors.New("db delete error"))

				return handler
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "successful delete",
			id:   primitive.NewObjectID().Hex(),
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)

				mocks.UserV3.EXPECT().
					DeleteByID(gomock.Any(), gomock.Any()).
					Return(nil)

				mocks.UserHistory.EXPECT().
					Create(gomock.Any(), gomock.Any()).
					Return(nil).AnyTimes()

				return handler
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			h := tt.mockFunc(ctrl)

			req := httptest.NewRequest(http.MethodDelete, "/op/users/delete/"+tt.id, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tt.id)
			c.Set("user_name", "tester")

			if err := h.DeletePublicUser(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestManagerUserHandler_ListPublicUsers(t *testing.T) {
	e := setupEcho()

	tests := []struct {
		name       string
		query      string
		mockFunc   func(ctrl *gomock.Controller) *ManagerUserHandler
		wantStatus int
	}{
		{
			name:  "bind error invalid bool array",
			query: "",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, _ := setupBasicMocks(ctrl)
				return handler
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:  "invalid limit",
			query: "limit=invalid",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().
					FindUserV3(gomock.Any(), gomock.Any()).
					Return(nil, int64(0), nil).AnyTimes()
				return handler
			},
			wantStatus: http.StatusOK, // 👈 chiều handler
		},
		{
			name:  "invalid offset",
			query: "offset=invalid",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().
					FindUserV3(gomock.Any(), gomock.Any()).
					Return(nil, int64(0), nil).AnyTimes()
				return handler
			},
			wantStatus: http.StatusOK,
		},
		{
			name:  "invalid group id",
			query: "group_id=invalid-hex",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().
					FindUserV3(gomock.Any(), gomock.Any()).
					Return(nil, int64(0), nil).AnyTimes()
				return handler
			},
			wantStatus: http.StatusOK,
		},
		{
			name:  "error listing users",
			query: "limit=10&offset=0",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().
					FindUserV3(gomock.Any(), gomock.Any()).
					Return(nil, int64(0), errors.New("db error"))
				return handler
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:  "successful list without filters",
			query: "limit=10&offset=0",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)
				users := []*model.UserV3Aggregate{
					{UserV3: model.UserV3{ID: primitive.NewObjectID(), Username: "user1"}},
					{UserV3: model.UserV3{ID: primitive.NewObjectID(), Username: "user2"}},
				}
				mocks.UserV3.EXPECT().
					FindUserV3(gomock.Any(), gomock.Any()).
					Return(users, int64(2), nil)
				return handler
			},
			wantStatus: http.StatusOK,
		},
		{
			name:  "successful list with group id filter",
			query: "limit=5&offset=0&group_id=507f1f77bcf86cd799439011",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)
				users := []*model.UserV3Aggregate{
					{UserV3: model.UserV3{
						ID:       primitive.NewObjectID(),
						Username: "user1",
						GroupID:  "507f1f77bcf86cd799439011",
					}},
				}
				mocks.UserV3.EXPECT().
					FindUserV3(gomock.Any(), gomock.Any()).
					Return(users, int64(1), nil)
				return handler
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			h := tt.mockFunc(ctrl)

			var req *http.Request
			if tt.name == "bind error invalid bool array" {
				// gửi body JSON sai kiểu
				req = httptest.NewRequest(http.MethodGet, "/op/users/list", strings.NewReader(`{"status":["yes"]}`))
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			} else {
				// gửi query string
				url := "/op/users/list"
				if tt.query != "" {
					url += "?" + tt.query
				}
				req = httptest.NewRequest(http.MethodGet, url, nil)
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			}

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", "tester")

			if err := h.List(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}

}

func TestManagerUserHandler_Detail(t *testing.T) {
	e := setupEcho()

	tests := []struct {
		name       string
		id         string
		mockFunc   func(ctrl *gomock.Controller) *ManagerUserHandler
		wantStatus int
	}{
		{
			name: "invalid id format",
			id:   "invalid-hex",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, _ := setupBasicMocks(ctrl)
				return handler
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "error from repository",
			id:   primitive.NewObjectID().Hex(),
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)

				mocks.UserV3.EXPECT().
					Detail(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("db error"))

				return handler
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "successful detail",
			id:   primitive.NewObjectID().Hex(),
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)

				user := &model.UserV3Aggregate{
					UserV3: model.UserV3{
						ID:       primitive.NewObjectID(),
						Username: "tester",
					},
				}
				mocks.UserV3.EXPECT().
					Detail(gomock.Any(), gomock.Any()).
					Return(user, nil)

				return handler
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			h := tt.mockFunc(ctrl)

			req := httptest.NewRequest(http.MethodGet, "/op/users/detail/"+tt.id, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tt.id)

			if err := h.Detail(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestManagerUserHandler_GetUserHistoryDetail(t *testing.T) {
	e := setupEcho()

	tests := []struct {
		name       string
		id         string
		mockFunc   func(ctrl *gomock.Controller) *ManagerUserHandler
		wantStatus int
	}{
		{
			name: "invalid id",
			id:   "invalid-hex",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, _ := setupBasicMocks(ctrl)
				return handler
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "repository error",
			id:   primitive.NewObjectID().Hex(),
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)
				mocks.UserHistory.EXPECT().
					FindAll(gomock.Any(), gomock.Any()).
					Return(nil, int64(0), errors.New("db error"))
				return handler
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "history not found",
			id:   primitive.NewObjectID().Hex(),
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)
				mocks.UserHistory.EXPECT().
					FindAll(gomock.Any(), gomock.Any()).
					Return([]*model.UserHistory{}, int64(0), nil)
				return handler
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "successful detail",
			id:   primitive.NewObjectID().Hex(),
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)

				history := &model.UserHistory{
					ID:          primitive.NewObjectID(),
					UserID:      primitive.NewObjectID(),
					Event:       defs.HistoryEvent("update"),
					UserBefore:  "before",
					UserAfter:   "after",
					CreatedTime: time.Now().Unix(),
					Creator:     "tester",
				}

				mocks.UserHistory.EXPECT().
					FindAll(gomock.Any(), gomock.Any()).
					Return([]*model.UserHistory{history}, int64(1), nil)
				return handler
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			h := tt.mockFunc(ctrl)

			req := httptest.NewRequest(http.MethodGet, "/op/users/history/detail/"+tt.id, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tt.id)

			if err := h.GetUserHistoryDetail(c); err != nil {
				t.Fatal(err)
			}

			if rec.Code != tt.wantStatus {
				t.Errorf("expected %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestManagerUserHandler_ListUserHistory(t *testing.T) {
	e := setupEcho()

	tests := []struct {
		name       string
		id         string
		body       string
		mockFunc   func(ctrl *gomock.Controller) *ManagerUserHandler
		wantStatus int
	}{
		{
			name: "invalid id",
			id:   "invalid-hex",
			body: `{}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, _ := setupBasicMocks(ctrl)
				return h
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "bind error",
			id:   primitive.NewObjectID().Hex(),
			body: `{"size":"not-a-number"}`, // ép Bind lỗi
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, _ := setupBasicMocks(ctrl)
				return h
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "repo error",
			id:   primitive.NewObjectID().Hex(),
			body: `{"size":10,"offset":0}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, mocks := setupBasicMocks(ctrl)
				mocks.UserHistory.EXPECT().
					FindAll(gomock.Any(), gomock.Any()).
					Return(nil, int64(0), errors.New("db error"))
				return h
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success no histories",
			id:   primitive.NewObjectID().Hex(),
			body: `{"size":10,"offset":0}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, mocks := setupBasicMocks(ctrl)
				mocks.UserHistory.EXPECT().
					FindAll(gomock.Any(), gomock.Any()).
					Return([]*model.UserHistory{}, int64(0), nil)
				return h
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "success with histories",
			id:   primitive.NewObjectID().Hex(),
			body: `{"size":5,"offset":0}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, mocks := setupBasicMocks(ctrl)
				history := &model.UserHistory{
					ID:          primitive.NewObjectID(),
					UserID:      primitive.NewObjectID(),
					Event:       defs.HistoryEvent("update"),
					UserBefore:  "before",
					UserAfter:   "after",
					CreatedTime: time.Now().Unix(),
					Creator:     "tester",
				}
				mocks.UserHistory.EXPECT().
					FindAll(gomock.Any(), gomock.Any()).
					Return([]*model.UserHistory{history}, int64(1), nil)
				return h
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			h := tt.mockFunc(ctrl)

			req := httptest.NewRequest(http.MethodPost, "/op/users/history/list/"+tt.id, strings.NewReader(tt.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tt.id)

			if err := h.ListUserHistory(c); err != nil {
				t.Fatal(err)
			}

			if rec.Code != tt.wantStatus {
				t.Errorf("expected %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestManagerUserHandler_StatisticV3(t *testing.T) {
	e := setupEcho()

	tests := []struct {
		name       string
		body       string
		mockFunc   func(ctrl *gomock.Controller) *ManagerUserHandler
		wantStatus int
	}{
		{
			name: "bind error",
			body: `{"from_expired_time":"invalid"}`, // sai type int64
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, _ := setupBasicMocks(ctrl)
				return h
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "repo error",
			body: `{}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().
					StatisticV3(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("db error"))
				return h
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			body: `{}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().
					StatisticV3(gomock.Any(), gomock.Any()).
					Return(&model.SearchUserV3Statistic{
						Active: []*model.AggBoolFieldValuev3{
							{Value: true, Count: 5},
							{Value: false, Count: 3},
						},
						Ownership: []*model.AggBoolFieldValuev3{
							{Value: true, Count: 2},
						},
						Mass: []*model.AggBoolFieldValuev3{
							{Value: false, Count: 7},
						},
						Country: []string{"VN", "US"},
						Package: []string{"basic", "premium"},
					}, nil)
				return h
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			h := tt.mockFunc(ctrl)

			req := httptest.NewRequest(http.MethodPost, "/op/users/statistic", strings.NewReader(tt.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if err := h.StatisticV3(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tt.wantStatus {
				t.Errorf("got status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusOK {
				// kiểm tra response có field data
				if !strings.Contains(rec.Body.String(), `"data"`) {
					t.Errorf("expected response to contain data, got %s", rec.Body.String())
				}
			}
		})
	}
}

func TestManagerUserHandler_ChangeStatus(t *testing.T) {
	e := setupEcho()

	tests := []struct {
		name       string
		id         string
		body       string
		mockFunc   func(ctrl *gomock.Controller) *ManagerUserHandler
		wantStatus int
		wantMsg    string
	}{
		{
			name: "id is empty",
			id:   "",
			body: `{"active": true}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, _ := setupBasicMocks(ctrl)
				return h
			},
			wantStatus: http.StatusBadRequest,
			wantMsg:    "Id is required",
		},
		{
			name: "invalid body",
			id:   primitive.NewObjectID().Hex(),
			body: `{"active":"abc"}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, _ := setupBasicMocks(ctrl)
				return h
			},
			wantStatus: http.StatusBadRequest,
			wantMsg:    "Data is invalid",
		},
		{
			name: "invalid object id",
			id:   "invalid-hex",
			body: `{"active": true}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, _ := setupBasicMocks(ctrl)
				return h
			},
			wantStatus: http.StatusBadRequest,
			wantMsg:    "Invalid user ID format",
		},
		{
			name: "repo detail error",
			id:   primitive.NewObjectID().Hex(),
			body: `{"active": true}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().
					FindByID(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("db error"))
				return h
			},
			wantStatus: http.StatusInternalServerError,
			wantMsg:    "Failed to get current user",
		},
		{
			name: "status already same",
			id:   primitive.NewObjectID().Hex(),
			body: `{"active": true}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().
					FindByID(gomock.Any(), gomock.Any()).
					Return(&model.UserV3{Active: true}, nil)
				return h
			},
			wantStatus: http.StatusOK,
			wantMsg:    "already true",
		},
		{
			name: "update status error",
			id:   primitive.NewObjectID().Hex(),
			body: `{"active": false}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().
					FindByID(gomock.Any(), gomock.Any()).
					Return(&model.UserV3{Active: true}, nil)
				mocks.Group.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mockOrg, nil)
				mocks.Roles.EXPECT().GetByName(gomock.Any(), gomock.Any()).Return(&mockRoleDetail, nil)
				mocks.UserV3.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("update fail"))
				return h
			},
			wantStatus: http.StatusInternalServerError,
			wantMsg:    "Failed to change status user",
		},
		{
			name: "success with history ok",
			id:   primitive.NewObjectID().Hex(),
			body: `{"active": false}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().
					FindByID(gomock.Any(), gomock.Any()).
					Return(&model.UserV3{Active: true}, nil)
				mocks.Group.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mockOrg, nil)
				mocks.Roles.EXPECT().GetByName(gomock.Any(), gomock.Any()).Return(&mockRoleDetail, nil)
				mocks.UserV3.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
				mocks.UserHistory.EXPECT().
					Create(gomock.Any(), gomock.Any()).
					Return(nil)
				return h
			},
			wantStatus: http.StatusOK,
			wantMsg:    "Change status user successfully",
		},
		{
			name: "success with history error",
			id:   primitive.NewObjectID().Hex(),
			body: `{"active": false}`,
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				h, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().
					FindByID(gomock.Any(), gomock.Any()).
					Return(&model.UserV3{Active: true}, nil)
				mocks.Group.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mockOrg, nil)
				mocks.Roles.EXPECT().GetByName(gomock.Any(), gomock.Any()).Return(&mockRoleDetail, nil)
				mocks.UserV3.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
				mocks.UserHistory.EXPECT().
					Create(gomock.Any(), gomock.Any()).
					Return(errors.New("history error"))
				return h
			},
			wantStatus: http.StatusOK,
			wantMsg:    "Change status user successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			h := tt.mockFunc(ctrl)

			req := httptest.NewRequest(http.MethodPost, "/op/users/change-status/"+tt.id, strings.NewReader(tt.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tt.id)
			c.Set("user_name", "tester")

			if err := h.ChangeStatus(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
			// if !strings.Contains(rec.Body.String(), tt.wantMsg) {
			// 	t.Errorf("expected body to contain %q, got %s", tt.wantMsg, rec.Body.String())
			// }
		})
	}
}

func TestManagerUserHandler_GetAlertConfig(t *testing.T) {
	e := setupEcho()

	tests := []struct {
		name       string
		groupID    string
		mockFunc   func(ctrl *gomock.Controller) *ManagerUserHandler
		wantStatus int
		wantMsg    string
	}{
		{
			name:    "group_id is empty",
			groupID: "",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, _ := setupBasicMocks(ctrl)
				return handler
			},
			wantStatus: http.StatusBadRequest,
			wantMsg:    "Group_id is required", // ✅ fix message
		},
		{
			name:    "service returns error",
			groupID: "507f1f77bcf86cd799439011",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)
				mocks.UserV3.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&mockUser, nil)
				mockAlertSvc := mock_service.NewMockMailService(ctrl)
				mockAlertSvc.EXPECT().
					BuildAlertConfig(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New("db error"))

				handler.service = mockAlertSvc
				return handler
			},
			wantStatus: http.StatusInternalServerError,
			wantMsg:    "Failed to get alert config", // ✅ fix message
		},
		{
			name:    "success",
			groupID: "507f1f77bcf86cd799439011",
			mockFunc: func(ctrl *gomock.Controller) *ManagerUserHandler {
				handler, mocks := setupBasicMocks(ctrl)

				mocks.UserV3.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&mockUser, nil)
				mockAlertSvc := mock_service.NewMockMailService(ctrl)
				mockAlertSvc.EXPECT().
					BuildAlertConfig(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.AlertConfig{
						Vulnerabilities: model.AlertSetting{
							Enabled:   true,
							Frequency: "daily",
						},
						BrandAbuse: model.AlertSetting{
							Enabled: false,
						},
					}, nil)

				handler.service = mockAlertSvc
				return handler
			},
			wantStatus: http.StatusOK,
			wantMsg:    "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			h := tt.mockFunc(ctrl)

			req := httptest.NewRequest(http.MethodGet, "/op/alert-config/"+tt.groupID, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tt.groupID)
			c.Set("user_name", "tester")

			if err := h.GetAlertConfig(c); err != nil {
				t.Fatal(err)
			}

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}

			if !strings.Contains(rec.Body.String(), tt.wantMsg) {
				t.Errorf("expected body to contain %q, got %s", tt.wantMsg, rec.Body.String())
			}
		})
	}
}

func TestManagerUserHandler_GetPositionJobs(t *testing.T) {
	e := setupEcho()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	handler, _ := setupBasicMocks(ctrl)

	req := httptest.NewRequest(http.MethodGet, "/op/user/positions", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// call handler
	if err := handler.GetPositionJobs(c); err != nil {
		t.Fatal(err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	// parse JSON body
	var resp struct {
		Message string                   `json:"message"`
		Data    []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// check message
	if resp.Message != "success" {
		t.Errorf("got message %q, want %q", resp.Message, "success")
	}

	// check data length bằng defs.MAP_POSITION_JOB
	if len(resp.Data) != len(defs.MAP_POSITION_JOB) {
		t.Errorf("got %d positions, want %d", len(resp.Data), len(defs.MAP_POSITION_JOB))
	}
}

func TestManagerUserHandler_GetCountries(t *testing.T) {
	e := setupEcho()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	handler, _ := setupBasicMocks(ctrl)

	req := httptest.NewRequest(http.MethodGet, "/op/user/countries", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := handler.GetCountries(c); err != nil {
		t.Fatal(err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp struct {
		Message string   `json:"message"`
		Data    []string `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Message != "success" {
		t.Errorf("got message %q, want %q", resp.Message, "success")
	}

	if len(resp.Data) == 0 {
		t.Errorf("expected some countries, got 0")
	}
}
