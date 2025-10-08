package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	mock_repo "gitlab.viettelcyber.com/ti-micro/ws-customer/mock/repo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/mock/gomock"
)

func ptrBool(b bool) *bool {
	return &b
}

func ptrString(s string) *string {
	return &s
}

func TestRoleHandler_Search(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRolesRepo := mock_repo.NewMockRolesRepository(ctrl)
	mockAccount := mock_repo.NewMockAccountRepository(ctrl)
	mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
	mockAccount.EXPECT().Roles().Return(mockRolesRepo).AnyTimes()
	mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
	h := &RoleHandler{mongo: mockMongo}
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}
	notFoundString := "not found"
	tests := []struct {
		name           string
		requestBody    *model.RequestRoleSearch
		setupMock      func(mockRoles *mock_repo.MockRolesRepository)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Invalid request - bad type",
			requestBody:    &model.RequestRoleSearch{Type: []string{"invalid_type"}},
			setupMock:      func(m *mock_repo.MockRolesRepository) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Success - empty result",
			requestBody: &model.RequestRoleSearch{
				RequestRoleStatistic: model.RequestRoleStatistic{
					Keyword: "test",
				},
				Size:   10,
				Offset: 0,
			},
			setupMock: func(m *mock_repo.MockRolesRepository) {
				m.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Role{}, nil).Times(1)
				m.EXPECT().
					Count(gomock.Any(), gomock.Any()).
					Return(int64(0), nil).Times(1)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   `"total":0`,
		},
		{
			name: "DB error on Find",
			requestBody: &model.RequestRoleSearch{
				RequestRoleStatistic: model.RequestRoleStatistic{
					Keyword: "x",
				},
				Size:   5,
				Offset: 0,
			},
			setupMock: func(m *mock_repo.MockRolesRepository) {
				m.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New("some db error")).Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Find returns NotFound -> OK empty data (cover NotFound branch)",
			requestBody: &model.RequestRoleSearch{
				RequestRoleStatistic: model.RequestRoleStatistic{
					Keyword: "whatever",
				},
				Size:   10,
				Offset: 0,
			},
			setupMock: func(m *mock_repo.MockRolesRepository) {
				m.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New(notFoundString)).Times(1)
				m.EXPECT().Count(gomock.Any(), gomock.Any()).Times(0)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   `"total":0`,
		},
		{
			name: "Find OK but Count error -> InternalServerError (cover Count error branch)",
			requestBody: &model.RequestRoleSearch{
				RequestRoleStatistic: model.RequestRoleStatistic{
					Keyword: "ok_but_count_fail",
				},
				Size:   10,
				Offset: 0,
			},
			setupMock: func(m *mock_repo.MockRolesRepository) {
				m.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Role{{ID: "r1", RoleID: "ROLE1"}}, nil).Times(1)
				m.EXPECT().
					Count(gomock.Any(), gomock.Any()).
					Return(int64(0), errors.New("count error")).Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupMock != nil {
				tt.setupMock(mockRolesRepo)
			}
			b, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/search", bytes.NewReader(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := h.Search(c)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, rec.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestRoleHandler_DeleteRole(t *testing.T) {
	tests := []struct {
		name            string
		requestBody     *model.RequestRoleID
		setupMock       func(rm *mock_repo.MockRolesRepository, gm *mock_repo.MockGroupUserRepository)
		expectedStatus  int
		expectedMessage string
	}{
		{
			name:        "Role Not Found",
			requestBody: &model.RequestRoleID{ID: "r7"},
			setupMock: func(rm *mock_repo.MockRolesRepository, gm *mock_repo.MockGroupUserRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "r7").
					Return(nil, errors.New("not found")).
					Times(1)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:        "Delete Role Success",
			requestBody: &model.RequestRoleID{ID: "r7"},
			setupMock: func(rm *mock_repo.MockRolesRepository, gm *mock_repo.MockGroupUserRepository) {
				role := &model.Role{RoleID: "ROLE7", ID: "r7"}
				rm.EXPECT().
					GetByName(gomock.Any(), "r7").
					Return(role, nil).
					Times(1)
				gm.EXPECT().
					GetByRole(gomock.Any(), role.RoleID).
					Return(nil, nil).
					Times(1)
				rm.EXPECT().
					DeleteByID(gomock.Any(), role.ID).
					Return(nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "Internal Server Error on GetByName",
			requestBody: &model.RequestRoleID{ID: "r7"},
			setupMock: func(rm *mock_repo.MockRolesRepository, gm *mock_repo.MockGroupUserRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "r7").
					Return(nil, errors.New("unexpected database error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Delete Role Database Error",
			requestBody: &model.RequestRoleID{ID: "r7"},
			setupMock: func(rm *mock_repo.MockRolesRepository, gm *mock_repo.MockGroupUserRepository) {
				role := &model.Role{RoleID: "ROLE7", ID: "r7"}

				rm.EXPECT().
					GetByName(gomock.Any(), "r7").
					Return(role, nil).
					Times(1)

				gm.EXPECT().
					GetByRole(gomock.Any(), role.RoleID).
					Return(nil, nil).
					Times(1)

				rm.EXPECT().
					DeleteByID(gomock.Any(), role.ID).
					Return(errors.New("database delete error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Error Getting Organization by Role",
			requestBody: &model.RequestRoleID{ID: "r7"},
			setupMock: func(rm *mock_repo.MockRolesRepository, gm *mock_repo.MockGroupUserRepository) {
				role := &model.Role{RoleID: "ROLE7", ID: "r7"}
				rm.EXPECT().
					GetByName(gomock.Any(), "r7").
					Return(role, nil).
					Times(1)
				gm.EXPECT().
					GetByRole(gomock.Any(), role.RoleID).
					Return(nil, errors.New("database error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Role Associated with Organization",
			requestBody: &model.RequestRoleID{ID: "r7"},
			setupMock: func(rm *mock_repo.MockRolesRepository, gm *mock_repo.MockGroupUserRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "r7").
					Return(&model.Role{RoleID: "r7"}, nil).
					AnyTimes()
				organization := &model.GroupUser{ID: "org1", Role: "r7"}
				gm.EXPECT().
					GetByRole(gomock.Any(), "r7").
					Return(organization, nil).
					Times(1)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Invalid Request Body",
			requestBody: &model.RequestRoleID{ID: ""},
			setupMock: func(rm *mock_repo.MockRolesRepository, gm *mock_repo.MockGroupUserRepository) {
			},
			expectedStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockRolesRepo := mock_repo.NewMockRolesRepository(ctrl)
			mockGroupUserRepo := mock_repo.NewMockGroupUserRepository(ctrl)
			mockAccount := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccount.EXPECT().Roles().Return(mockRolesRepo).AnyTimes()
			mockAccount.EXPECT().GroupUser().Return(mockGroupUserRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()

			tt.setupMock(mockRolesRepo, mockGroupUserRepo)

			h := &RoleHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}

			b, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodDelete, "/:id", bytes.NewReader(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := h.DeleteRole(c)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			t.Logf("Response Status: %d", rec.Code)
			t.Logf("Response Body: %s", rec.Body.String())
			t.Logf("Response Headers: %v", rec.Header())

			if tt.expectedStatus == http.StatusBadRequest {
				var response map[string]interface{}
				json.Unmarshal(rec.Body.Bytes(), &response)
				assert.Equal(t, false, response["success"])
			}
		})
	}
}

func TestRoleHandler_DetailRole(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    *model.RequestRoleID
		setupMock      func(rm *mock_repo.MockRolesRepository)
		expectedStatus int
		expectMessage  string
	}{
		{
			name: "Invalid Request Body",
			requestBody: &model.RequestRoleID{
				ID: "",
			},
			setupMock:      func(rm *mock_repo.MockRolesRepository) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Detail Role",
			requestBody: &model.RequestRoleID{
				ID: "role_1",
			},
			setupMock: func(rm *mock_repo.MockRolesRepository) {
				role := &model.Role{RoleID: "role_1"}
				rm.EXPECT().
					GetByName(gomock.Any(), "role_1").
					Return(role, nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "Detail Role Error",
			requestBody: &model.RequestRoleID{ID: "role_1"},
			setupMock: func(rm *mock_repo.MockRolesRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "role_1").
					Return(nil, errors.New(" database error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Role not found",
			requestBody: &model.RequestRoleID{ID: "role_1"},
			setupMock: func(rm *mock_repo.MockRolesRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "role_1").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)
			},
			expectedStatus: http.StatusNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockRolesRepo := mock_repo.NewMockRolesRepository(ctrl)
			mockAccount := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccount.EXPECT().Roles().Return(mockRolesRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
			tc.setupMock(mockRolesRepo)

			h := &RoleHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}
			t.Logf("RequestBody: %+v", tc.requestBody)
			jsonBody, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest(http.MethodGet, "/"+tc.requestBody.ID, bytes.NewBuffer(jsonBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := h.DetailRole(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestRoleHandler_CreateRole(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    *model.RequestRoleCreate
		setupMock      func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository)
		expectedStatus int
		expectMessage  string
	}{
		{
			name: "Invalid Request Body - Empty Role ID",
			requestBody: &model.RequestRoleCreate{
				RoleID: "",
			},
			setupMock: func(
				rm *mock_repo.MockRolesRepository,
				fm *mock_repo.MockFeaturesRepository,
				pm *mock_repo.MockPermissionsRepository) {
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Successful Role Creation",
			requestBody: &model.RequestRoleCreate{
				RoleID:      "new_role",
				Description: "vi",
				Month:       12,
				Language:    "vi",
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Level:              2,
				Type:               "mass",
				LimitAlert:         2,
				LimitAccount:       2,
				LimitProduct:       2,
				LimitAliases:       2,
				LimitIPDomain:      2,
				ReportPackage:      ptrBool(true),
				PaygatePackage:     ptrString("paygate_pkg1"),
				PaygatePackageName: ptrString("paygate_name"),
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "new_role").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)

				rm.EXPECT().
					GetByName(gomock.Any(), "paygate_pkg1").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)

				fm.EXPECT().
					GetByCode(gomock.Any(), gomock.Any(), int64(0), int64(1)).
					Return([]*model.Feature{
						{Code: "easm"},
					}, nil).
					Times(1)

				pm.EXPECT().
					GetAll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Permissions{
						{PermissionId: "easm"},
					}, nil).
					Times(1)

				rm.EXPECT().
					Store(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Mass error",
			requestBody: &model.RequestRoleCreate{
				RoleID:      "new_role",
				Description: "vi",
				Month:       12,
				Language:    "vi",
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Level:              2,
				Type:               "mass",
				LimitAlert:         2,
				LimitAccount:       2,
				LimitProduct:       2,
				LimitAliases:       2,
				LimitIPDomain:      2,
				ReportPackage:      ptrBool(true),
				PaygatePackage:     ptrString("paygate_pkg1"),
				PaygatePackageName: ptrString("paygate_name"),
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), gomock.Any()).
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)

				rm.EXPECT().
					GetByName(gomock.Any(), "paygate_pkg1").
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Paygate Package already exists in another Package",
			requestBody: &model.RequestRoleCreate{
				RoleID:      "new_role",
				Description: "vi",
				Month:       12,
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Language:           "vi",
				Level:              2,
				Type:               "mass",
				LimitAlert:         2,
				LimitAccount:       2,
				LimitProduct:       2,
				LimitAliases:       2,
				LimitIPDomain:      2,
				ReportPackage:      ptrBool(true),
				PaygatePackage:     ptrString("paygate_pkg1"),
				PaygatePackageName: ptrString("paygate_name"),
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "new_role").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)

				rm.EXPECT().
					GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{
						PriceListID:        ptrString("paygate_pkg1"),
						PaygatePackageName: ptrString("paygate_name"),
					}, nil).
					Times(1)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Role Already Exists",
			requestBody: &model.RequestRoleCreate{
				RoleID:      "existing_role",
				Description: "vi",
				Month:       12,
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Language:      "vi",
				Level:         2,
				Type:          "enterprise",
				LimitAlert:    2,
				LimitAccount:  2,
				LimitProduct:  2,
				LimitAliases:  2,
				LimitIPDomain: 2,
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				role := &model.Role{RoleID: "existing_role"}
				rm.EXPECT().
					GetByName(gomock.Any(), "existing_role").
					Return(role, nil).
					Times(1)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Role error",
			requestBody: &model.RequestRoleCreate{
				RoleID:      "existing_role",
				Description: "vi",
				Month:       12,
				Language:    "vi",
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Level:         2,
				Type:          "enterprise",
				LimitAlert:    2,
				LimitAccount:  2,
				LimitProduct:  2,
				LimitAliases:  2,
				LimitIPDomain: 2,
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "existing_role").
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Privileges error",
			requestBody: &model.RequestRoleCreate{
				RoleID:      "existing_role",
				Description: "vi",
				Month:       12,
				Language:    "vi",
				Level:       2,
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
					"easm1": {
						"read": true,
					},
				},
				Type:          "enterprise",
				LimitAccount:  2,
				LimitAlert:    2,
				LimitProduct:  2,
				LimitAliases:  2,
				LimitIPDomain: 2,
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "existing_role").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)

				fm.EXPECT().
					GetByCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Feature{{Code: "easm"}}, nil).Times(1)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Store Role Error",
			requestBody: &model.RequestRoleCreate{
				RoleID:      "new_role",
				Description: "vi",
				Month:       12,
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Language:      "vi",
				Level:         2,
				Type:          "enterprise",
				LimitAlert:    2,
				LimitAccount:  2,
				LimitProduct:  2,
				LimitAliases:  2,
				LimitIPDomain: 2,
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "new_role").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)

				fm.EXPECT().
					GetByCode(gomock.Any(), gomock.Any(), int64(0), int64(1)).
					Return([]*model.Feature{
						{Code: "easm"},
					}, nil).
					Times(1)

				pm.EXPECT().
					GetAll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Permissions{
						{PermissionId: "easm"},
					}, nil).
					Times(1)

				rm.EXPECT().
					Store(gomock.Any(), gomock.Any()).
					Return(errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockRolesRepo := mock_repo.NewMockRolesRepository(ctrl)
			mockFeaturesRepo := mock_repo.NewMockFeaturesRepository(ctrl)
			mockPermissionsRepo := mock_repo.NewMockPermissionsRepository(ctrl)
			mockAccountRepo := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccountRepo.EXPECT().Roles().Return(mockRolesRepo).AnyTimes()
			mockAccountRepo.EXPECT().Features().Return(mockFeaturesRepo).AnyTimes()
			mockAccountRepo.EXPECT().Permissions().Return(mockPermissionsRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccountRepo).AnyTimes()

			tc.setupMock(mockRolesRepo, mockFeaturesRepo, mockPermissionsRepo)

			h := &RoleHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}

			t.Logf("RequestBody: %+v", tc.requestBody)
			b, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", "test_user")
			err := h.CreateRole(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestRoleHandler_EditRole(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    *model.RequestRoleEdit
		setupMock      func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository)
		expectedStatus int
		expectMessage  string
	}{
		{
			name: "Invalid Request Body - Empty Role ID",
			requestBody: &model.RequestRoleEdit{
				ID: "",
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Successful Role Edit with type enterprise",
			requestBody: &model.RequestRoleEdit{
				ID:          "role1",
				Description: "vi",
				Month:       12,
				Language:    "vi",
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Level:         2,
				Type:          "enterprise",
				LimitAccount:  2,
				LimitAlert:    2,
				LimitProduct:  2,
				LimitAliases:  2,
				LimitIPDomain: 2,
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				role := &model.Role{
					ID:        "123",
					RoleID:    "role1",
					MultiLang: make(map[string]model.LanguageContent),
					Languages: []string{},
				}

				rm.EXPECT().
					GetByName(gomock.Any(), "role1").
					Return(role, nil).
					Times(1)

				fm.EXPECT().
					GetByCode(gomock.Any(), gomock.Any(), int64(0), int64(1)).
					Return([]*model.Feature{
						{Code: "easm"},
					}, nil).
					Times(1)

				pm.EXPECT().
					GetAll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Permissions{
						{PermissionId: "easm"},
					}, nil).
					Times(1)

				rm.EXPECT().
					UpdateByID(gomock.Any(), role.ID, role).
					Return(nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Successful Role Edit with type enterprise - jp",
			requestBody: &model.RequestRoleEdit{
				ID:          "role1",
				Description: "vi",
				Month:       12,
				Language:    "jp",
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Level:         2,
				Type:          "enterprise",
				LimitAccount:  2,
				LimitAlert:    2,
				LimitProduct:  2,
				LimitAliases:  2,
				LimitIPDomain: 2,
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				role := &model.Role{
					ID:        "123",
					RoleID:    "role1",
					MultiLang: make(map[string]model.LanguageContent),
					Languages: []string{},
				}

				rm.EXPECT().
					GetByName(gomock.Any(), "role1").
					Return(role, nil).
					Times(1)

				fm.EXPECT().
					GetByCode(gomock.Any(), gomock.Any(), int64(0), int64(1)).
					Return([]*model.Feature{
						{Code: "easm"},
					}, nil).
					Times(1)

				pm.EXPECT().
					GetAll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Permissions{
						{PermissionId: "easm"},
					}, nil).
					Times(1)

				rm.EXPECT().
					UpdateByID(gomock.Any(), role.ID, role).
					Return(nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Successful Role Edit with type mass",
			requestBody: &model.RequestRoleEdit{
				ID:          "role1",
				Description: "vi",
				Month:       12,
				Language:    "en",
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Level:              2,
				Type:               "mass",
				LimitAccount:       2,
				LimitAlert:         2,
				LimitProduct:       2,
				LimitAliases:       2,
				LimitIPDomain:      2,
				ReportPackage:      ptrBool(true),
				PaygatePackage:     ptrString("paygate_pkg1"),
				PaygatePackageName: ptrString("paygate_name"),
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				role := &model.Role{
					ID:        "123",
					RoleID:    "role1",
					Mass:      true,
					MultiLang: make(map[string]model.LanguageContent),
					Languages: []string{},
				}

				rm.EXPECT().
					GetByName(gomock.Any(), "role1").
					Return(role, nil).
					Times(1)

				rm.EXPECT().
					GetByName(gomock.Any(), gomock.Any()).
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)

				fm.EXPECT().
					GetByCode(gomock.Any(), gomock.Any(), int64(0), int64(1)).
					Return([]*model.Feature{
						{Code: "easm"},
					}, nil).
					Times(1)

				pm.EXPECT().
					GetAll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Permissions{
						{PermissionId: "view_easm"},
					}, nil).
					Times(1)

				rm.EXPECT().
					UpdateByID(gomock.Any(), role.ID, role).
					Return(nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Privileges error",
			requestBody: &model.RequestRoleEdit{
				ID:          "role1",
				Description: "vi",
				Month:       12,
				Language:    "jp",
				Level:       2,
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Type:          "enterprise",
				LimitAccount:  2,
				LimitAlert:    2,
				LimitProduct:  2,
				LimitAliases:  2,
				LimitIPDomain: 2,
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{
						RoleID: "role1",
					}, nil).
					Times(1)

				fm.EXPECT().
					GetByCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New("error")).Times(1)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Privileges error not found",
			requestBody: &model.RequestRoleEdit{
				ID:          "role1",
				Description: "vi",
				Month:       12,
				Language:    "jp",
				Level:       2,
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Type:          "enterprise",
				LimitAccount:  2,
				LimitAlert:    2,
				LimitProduct:  2,
				LimitAliases:  2,
				LimitIPDomain: 2,
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{
						RoleID: "role1",
					}, nil).
					Times(1)

				fm.EXPECT().
					GetByCode(gomock.Any(), gomock.Any(), int64(0), int64(1)).
					Return([]*model.Feature{
						{Code: "easm"},
					}, nil).
					Times(1)

				pm.EXPECT().
					GetAll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Role Edit with type mass error",
			requestBody: &model.RequestRoleEdit{
				ID:          "role1",
				Description: "vi",
				Month:       12,
				Language:    "jp",
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Level:              2,
				Type:               "mass",
				LimitAccount:       2,
				LimitAlert:         2,
				LimitProduct:       2,
				LimitAliases:       2,
				LimitIPDomain:      2,
				ReportPackage:      ptrBool(true),
				PaygatePackage:     ptrString("paygate_pkg1"),
				PaygatePackageName: ptrString("paygate_name"),
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				role := &model.Role{
					ID:        "123",
					RoleID:    "role1",
					Mass:      true,
					MultiLang: make(map[string]model.LanguageContent),
					Languages: []string{},
				}

				rm.EXPECT().
					GetByName(gomock.Any(), "role1").
					Return(role, nil).
					Times(1)

				rm.EXPECT().
					GetByName(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Paygate Package already exists in another Package",
			requestBody: &model.RequestRoleEdit{
				ID:          "role1",
				Description: "vi",
				Month:       12,
				Language:    "jp",
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Level:              2,
				Type:               "mass",
				LimitAccount:       2,
				LimitAlert:         2,
				LimitProduct:       2,
				LimitAliases:       2,
				LimitIPDomain:      2,
				ReportPackage:      ptrBool(true),
				PaygatePackage:     ptrString("paygate_pkg1"),
				PaygatePackageName: ptrString("paygate_name"),
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				role := &model.Role{
					ID:        "123",
					RoleID:    "role1",
					Mass:      true,
					MultiLang: make(map[string]model.LanguageContent),
					Languages: []string{},
				}

				rm.EXPECT().
					GetByName(gomock.Any(), "role1").
					Return(role, nil).
					Times(1)

				rm.EXPECT().
					GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{PriceListID: ptrString("paygate_pkg1")}, nil).
					Times(1)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Role error",
			requestBody: &model.RequestRoleEdit{
				ID:          "existing_role",
				Description: "vi",
				Month:       12,
				Language:    "vi",
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Level:         2,
				Type:          "enterprise",
				LimitAccount:  2,
				LimitAlert:    2,
				LimitProduct:  2,
				LimitAliases:  2,
				LimitIPDomain: 2,
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "existing_role").
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Role not found",
			requestBody: &model.RequestRoleEdit{
				ID:          "existing_role",
				Description: "vi",
				Month:       12,
				Language:    "vi",
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Level:         2,
				Type:          "enterprise",
				LimitAlert:    2,
				LimitAccount:  2,
				LimitProduct:  2,
				LimitAliases:  2,
				LimitIPDomain: 2,
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				rm.EXPECT().
					GetByName(gomock.Any(), "existing_role").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "Update Role Error",
			requestBody: &model.RequestRoleEdit{
				ID:          "role1",
				Description: "vi",
				Month:       12,
				Language:    "vi",
				Level:       2,
				Privileges: map[string]map[string]bool{
					"easm": {
						"read": true,
					},
				},
				Type:          "enterprise",
				LimitAlert:    2,
				LimitAccount:  2,
				LimitProduct:  2,
				LimitAliases:  2,
				LimitIPDomain: 2,
			},
			setupMock: func(rm *mock_repo.MockRolesRepository, fm *mock_repo.MockFeaturesRepository, pm *mock_repo.MockPermissionsRepository) {
				role := &model.Role{
					ID:        "123",
					RoleID:    "role1",
					MultiLang: make(map[string]model.LanguageContent),
					Languages: []string{},
				}
				rm.EXPECT().
					GetByName(gomock.Any(), "role1").
					Return(role, nil).
					Times(1)

				fm.EXPECT().
					GetByCode(gomock.Any(), gomock.Any(), int64(0), int64(1)).
					Return([]*model.Feature{
						{Code: "easm"},
					}, nil).
					Times(1)

				pm.EXPECT().
					GetAll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Permissions{
						{PermissionId: "easm"},
					}, nil).
					Times(1)

				rm.EXPECT().
					UpdateByID(gomock.Any(), role.ID, role).
					Return(errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockRolesRepo := mock_repo.NewMockRolesRepository(ctrl)
			mockFeaturesRepo := mock_repo.NewMockFeaturesRepository(ctrl)
			mockPermissionsRepo := mock_repo.NewMockPermissionsRepository(ctrl)
			mockAccountRepo := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccountRepo.EXPECT().Roles().Return(mockRolesRepo).AnyTimes()
			mockAccountRepo.EXPECT().Features().Return(mockFeaturesRepo).AnyTimes()
			mockAccountRepo.EXPECT().Permissions().Return(mockPermissionsRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccountRepo).AnyTimes()

			tc.setupMock(mockRolesRepo, mockFeaturesRepo, mockPermissionsRepo)

			h := &RoleHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}

			t.Logf("RequestBody: %+v", tc.requestBody)
			b, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest(http.MethodPut, "/"+tc.requestBody.ID, bytes.NewReader(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", "test_user")
			err := h.EditRole(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestRoleHandler_Statistic(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    *model.RequestRoleStatistic
		setupMock      func(rm *mock_repo.MockRolesRepository)
		expectedStatus int
		expectMessage  string
	}{
		{
			name: "Valid Request Body",
			requestBody: &model.RequestRoleStatistic{
				Keyword:        "test",
				Level:          []int{0},
				Features:       []string{""},
				PaygatePackage: []string{""},
			},
			setupMock:      func(rm *mock_repo.MockRolesRepository) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Success",
			requestBody: &model.RequestRoleStatistic{
				Keyword:        "test",
				Level:          []int{1, 2},
				Features:       []string{"feat1"},
				PaygatePackage: []string{"pkg1"},
			},
			setupMock: func(rm *mock_repo.MockRolesRepository) {
				rm.EXPECT().
					AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(map[string][]mg.ResultAggregationCount{}, nil).
					Times(1)

				rm.EXPECT().
					AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(map[string][]mg.ResultAggregationCount{}, nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Error",
			requestBody: &model.RequestRoleStatistic{
				Keyword:        "test",
				Level:          []int{1, 2},
				Features:       []string{"feat1"},
				PaygatePackage: []string{"pkg1"},
			},
			setupMock: func(rm *mock_repo.MockRolesRepository) {
				rm.EXPECT().
					AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Success - with mass data processing",
			requestBody: &model.RequestRoleStatistic{
				Keyword:        "test",
				Level:          []int{1, 2},
				Features:       []string{"feat1"},
				PaygatePackage: []string{"pkg1"},
			},
			setupMock: func(rm *mock_repo.MockRolesRepository) {
				mockResult := map[string][]mg.ResultAggregationCount{
					"mass": {
						{Value: true, Count: 10},
						{Value: false, Count: 5},
					},
					"report_package": {
						{Value: true, Count: 8},
						{Value: false, Count: 7},
					},
					"level": {
						{Value: 1, Count: 3},
						{Value: 2, Count: 4},
						{Value: 3, Count: 2},
						{Value: 4, Count: 1},
					},
				}

				mockPaygateResult := map[string][]mg.ResultAggregationCount{
					"paygate_package": {
						{Value: "Name123", Count: 10},
						{Value: "Name12345", Count: 5},
					},
				}

				rm.EXPECT().
					AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(mockResult, nil).
					Times(1)

				rm.EXPECT().
					AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(mockPaygateResult, nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Error  paygate",
			requestBody: &model.RequestRoleStatistic{
				Keyword:        "test",
				Level:          []int{1, 2},
				Features:       []string{"feat1"},
				PaygatePackage: []string{"pkg1"},
			},
			setupMock: func(rm *mock_repo.MockRolesRepository) {
				mockResult := map[string][]mg.ResultAggregationCount{
					"mass": {
						{Value: true, Count: 10},
						{Value: false, Count: 5},
					},
					"report_package": {
						{Value: true, Count: 8},
						{Value: false, Count: 7},
					},
					"level": {
						{Value: 1, Count: 3},
						{Value: 2, Count: 4},
						{Value: 3, Count: 2},
						{Value: 4, Count: 1},
					},
				}
				rm.EXPECT().
					AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(mockResult, nil).
					Times(1)

				rm.EXPECT().
					AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockRolesRepo := mock_repo.NewMockRolesRepository(ctrl)
			mockAccount := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccount.EXPECT().Roles().Return(mockRolesRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
			tc.setupMock(mockRolesRepo)

			h := &RoleHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}

			jsonBody, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest(http.MethodGet, "/statistic", bytes.NewBuffer(jsonBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := h.Statistic(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestPrivilegesArrayToMap(t *testing.T) {
	tests := []struct {
		name     string
		input    []model.Privilege
		expected map[string]map[string]bool
	}{
		{
			name:     "Empty array",
			input:    []model.Privilege{},
			expected: map[string]map[string]bool{},
		},
		{
			name: "One privilege, one action",
			input: []model.Privilege{
				{Resource: "user", Action: []string{"read"}},
			},
			expected: map[string]map[string]bool{
				"user": {"read": true},
			},
		},
		{
			name: "One privilege, multiple actions",
			input: []model.Privilege{
				{Resource: "user", Action: []string{"read", "write"}},
			},
			expected: map[string]map[string]bool{
				"user": {"read": true, "write": true},
			},
		},
		{
			name: "Multiple privileges, different resources",
			input: []model.Privilege{
				{Resource: "user", Action: []string{"read", "write"}},
				{Resource: "order", Action: []string{"create"}},
			},
			expected: map[string]map[string]bool{
				"user":  {"read": true, "write": true},
				"order": {"create": true},
			},
		},
		{
			name: "Duplicate resource, override actions",
			input: []model.Privilege{
				{Resource: "user", Action: []string{"read"}},
				{Resource: "user", Action: []string{"delete", "update"}},
			},
			expected: map[string]map[string]bool{
				"user": {"delete": true, "update": true},
			},
		},
		{
			name: "Privilege with empty action",
			input: []model.Privilege{
				{Resource: "user", Action: []string{}},
			},
			expected: map[string]map[string]bool{"user": {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PrivilegesArrayToMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
