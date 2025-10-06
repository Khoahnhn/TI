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

//func Test_verifyRoleSearch(t *testing.T) {
//	e := echo.New()
//	e.Validator = &CustomValidator{validator: validator.New()}
//	tests := []struct {
//		name        string
//		body        string
//		wantErr     bool
//		wantKeyword string
//	}{
//		{
//			name:    "invalid type for keyword",
//			body:    `{"keyword": 123}`,
//			wantErr: true,
//		},
//		{
//			name:        "valid keyword with spaces",
//			body:        `{"keyword":"  testKeyword  "}`,
//			wantErr:     false,
//			wantKeyword: "testKeyword",
//		},
//		{
//			name:        "valid minimum valid input",
//			body:        `{"keyword":"valid","type":["mass"]}`,
//			wantErr:     false,
//			wantKeyword: "valid",
//		},
//		{
//			name:    "invalid type value",
//			body:    `{"keyword":"some","type":["invalid"]}`,
//			wantErr: true,
//		},
//		{
//			name:        "valid with report_package",
//			body:        `{"keyword":"abc","report_package":["true","false"], "type":["enterprise"]}`,
//			wantErr:     false,
//			wantKeyword: "abc",
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
//			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
//			rec := httptest.NewRecorder()
//			c := e.NewContext(req, rec)
//			h := &RoleHandler{}
//			got, err := h.verifyRoleSearch(c)
//			if tt.wantErr {
//				if err == nil {
//					t.Errorf("%s: expected error, got nil", tt.name)
//				}
//				return
//			}
//			if err != nil {
//				t.Errorf("%s: expected no error, got %v", tt.name, err)
//			}
//			wantTrimmed := strings.TrimSpace(tt.wantKeyword)
//			if got.Keyword != wantTrimmed {
//				t.Errorf("%s: expected keyword %q, got %q", tt.name, wantTrimmed, got.Keyword)
//			}
//		})
//	}
//}
//
//func Test_verifyRoleStatistic(t *testing.T) {
//	e := echo.New()
//	e.Validator = &CustomValidator{validator: validator.New()}
//
//	tests := []struct {
//		name               string
//		body               string
//		wantErr            bool
//		wantPaygatePackage []string
//		wantLevel          []int
//	}{
//		{
//			name:               "valid input with multiple levels and packages",
//			body:               `{"paygate_package":["pkg123","pkg456"],"level":[1,2,3]}`,
//			wantErr:            false,
//			wantPaygatePackage: []string{"pkg123", "pkg456"},
//			wantLevel:          []int{1, 2, 3},
//		},
//		{
//			name:               "valid input with one level and one package",
//			body:               `{"paygate_package":["single"],"level":[5]}`,
//			wantErr:            false,
//			wantPaygatePackage: []string{"single"},
//			wantLevel:          []int{5},
//		},
//		{
//			name:               "missing level field (valid omitempty)",
//			body:               `{"paygate_package":["pkg"]}`,
//			wantErr:            false,
//			wantPaygatePackage: []string{"pkg"},
//			wantLevel:          nil,
//		},
//		{
//			name:    "invalid level zero triggers validate error",
//			body:    `{"paygate_package":["pkg"],"level":[0]}`,
//			wantErr: true,
//		},
//		{
//			name:    "invalid JSON format",
//			body:    `{"paygate_package":"invalid"}`,
//			wantErr: true,
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
//			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
//			rec := httptest.NewRecorder()
//			c := e.NewContext(req, rec)
//			h := &RoleHandler{}
//			got, err := h.verifyRoleStatistic(c)
//			if tt.wantErr {
//				if err == nil {
//					t.Errorf("%s: expected error, got nil", tt.name)
//				}
//				return
//			}
//			if err != nil {
//				t.Errorf("%s: expected no error, got %v", tt.name, err)
//				return
//			}
//			if len(got.PaygatePackage) != len(tt.wantPaygatePackage) {
//				t.Errorf("%s: expected PaygatePackage length %d, got %d",
//					tt.name, len(tt.wantPaygatePackage), len(got.PaygatePackage))
//			} else {
//				for i := range got.PaygatePackage {
//					if got.PaygatePackage[i] != tt.wantPaygatePackage[i] {
//						t.Errorf("%s: expected PaygatePackage[%d] = %q, got %q",
//							tt.name, i, tt.wantPaygatePackage[i], got.PaygatePackage[i])
//					}
//				}
//			}
//			if len(got.Level) != len(tt.wantLevel) {
//				t.Errorf("%s: expected Level length %d, got %d",
//					tt.name, len(tt.wantLevel), len(got.Level))
//			} else {
//				for i := range got.Level {
//					if got.Level[i] != tt.wantLevel[i] {
//						t.Errorf("%s: expected Level[%d] = %v, got %v",
//							tt.name, i, tt.wantLevel[i], got.Level[i])
//					}
//				}
//			}
//		})
//	}
//}
//
//func TestRoleHandler_verifyRoleID(t *testing.T) {
//	e := echo.New()
//	e.Validator = &CustomValidator{validator: validator.New()}
//	tests := []struct {
//		name    string
//		body    string
//		wantErr bool
//		wantID  string
//	}{
//		{
//			name:    "valid RoleID",
//			body:    `{"id": "role123"}`,
//			wantErr: false,
//			wantID:  "role123",
//		},
//		{
//			name:    "missing ID field",
//			body:    `{}`,
//			wantErr: true,
//		},
//		{
//			name:    "empty ID string",
//			body:    `{"id": ""}`,
//			wantErr: true,
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
//			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
//			rec := httptest.NewRecorder()
//			c := e.NewContext(req, rec)
//			h := &RoleHandler{}
//			got, err := h.verifyRoleID(c)
//			if tt.wantErr {
//				if err == nil {
//					t.Errorf("%s: expected error, got nil", tt.name)
//				}
//				return
//			}
//			if err != nil {
//				t.Errorf("%s: expected no error, got %v", tt.name, err)
//				return
//			}
//			if got.ID != tt.wantID {
//				t.Errorf("%s: expected ID %q, got %q", tt.name, tt.wantID, got.ID)
//			}
//		})
//	}
//}
//
//func TestRoleHandler_verifyEdit(t *testing.T) {
//	ptrBool := func(b bool) *bool {
//		return &b
//	}
//	ptrString := func(s string) *string {
//		return &s
//	}
//	e := echo.New()
//	e.Validator = &CustomValidator{validator: validator.New()}
//	tests := []struct {
//		name         string
//		body         string
//		wantErr      bool
//		errMsgSubstr string
//		wantBody     model.RequestRoleEdit
//	}{
//		{
//			name: "valid input mass type with report and paygate package",
//			body: `{
//                "id": "role1",
//                "description": "valid description",
//                "type": "mass",
//                "month": 1,
//                "level": 1,
//                "language": "en",
//                "limit_account": 1,
//                "limit_ip_domain": 2,
//                "limit_product": 3,
//				"limit_alert": 1,
//                "limit_aliases": 4,
//                "permissions": ["perm1", "perm2"],
//                "report_package": true,
//                "paygate_package": "paygate123"
//            }`,
//			wantErr: false,
//			wantBody: model.RequestRoleEdit{
//				ID:             "role1",
//				Description:    "valid description",
//				Type:           "mass",
//				Month:          1,
//				Level:          1,
//				Language:       "en",
//				LimitAccount:   1,
//				LimitIPDomain:  2,
//				LimitAlert:     1,
//				LimitProduct:   3,
//				LimitAliases:   4,
//				ReportPackage:  ptrBool(true),
//				PaygatePackage: ptrString("paygate123"),
//			},
//		},
//		{
//			name: "mass type missing report_package",
//			body: `{
//                "id": "role3",
//                "description": "desc",
//                "type": "mass",
//                "month": 1,
//                "level": 1,
//                "language": "en",
//                "limit_account": 1,
//                "limit_ip_domain": 1,
//				"limit_alert": 1,
//                "limit_product": 1,
//                "limit_aliases": 1,
//                "permissions": ["permB"],
//                "paygate_package": "pg"
//            }`,
//			wantErr:      true,
//			errMsgSubstr: "report_package is required",
//		},
//		{
//			name: "mass type missing paygate_package",
//			body: `{
//                "id": "role4",
//                "description": "desc",
//                "type": "mass",
//                "month": 1,
//                "level": 1,
//                "language": "en",
//                "limit_account": 1,
//                "limit_ip_domain": 1,
//				"limit_alert": 1,
//                "limit_product": 1,
//                "limit_aliases": 1,
//                "permissions": ["permC"],
//                "report_package": true
//            }`,
//			wantErr:      true,
//			errMsgSubstr: "paygate is required",
//		},
//		{
//			name: "non mass type no report and paygate required",
//			body: `{
//                "id": "role5",
//                "description": "desc",
//                "type": "enterprise",
//                "month": 1,
//                "level": 1,
//                "language": "en",
//				"limit_alert": 1,
//                "limit_account": 1,
//                "limit_ip_domain": 1,
//                "limit_product": 1,
//                "limit_aliases": 1,
//                "permissions": ["permD"]
//            }`,
//			wantErr: false,
//			wantBody: model.RequestRoleEdit{
//				ID:             "role5",
//				Description:    "desc",
//				Type:           "enterprise",
//				Month:          1,
//				Level:          1,
//				Language:       "en",
//				LimitAccount:   1,
//				LimitAlert:     1,
//				LimitIPDomain:  1,
//				LimitProduct:   1,
//				LimitAliases:   1,
//				ReportPackage:  nil,
//				PaygatePackage: nil,
//			},
//		},
//		{
//			name: "validate error missing required id",
//			body: `{
//        "description": "desc",
//        "type": "mass",
//        "month": 1,
//        "level": 1,
//        "language": "en",
//        "limit_account": 1,
//		"limit_alert": 1,
//        "limit_ip_domain": 1,
//        "limit_product": 1,
//        "limit_aliases": 1,
//        "permissions": ["permA"],
//        "report_package": true,
//        "paygate_package": "pg"
//    }`,
//			wantErr:      true,
//			errMsgSubstr: "failed on the 'required' tag",
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(tt.body))
//			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
//			rec := httptest.NewRecorder()
//			c := e.NewContext(req, rec)
//			h := &RoleHandler{}
//			got, err := h.verifyEdit(c)
//			if tt.wantErr {
//				if err == nil {
//					t.Errorf("%s: expected error but got none", tt.name)
//				} else if !strings.Contains(err.Error(), tt.errMsgSubstr) {
//					t.Errorf("%s: expected error containing %q but got %v", tt.name, tt.errMsgSubstr, err)
//				}
//				return
//			}
//			if err != nil {
//				t.Errorf("%s: unexpected error: %v", tt.name, err)
//				return
//			}
//			if got.ID != tt.wantBody.ID {
//				t.Errorf("%s: ID want %q, got %q", tt.name, tt.wantBody.ID, got.ID)
//			}
//			if got.Description != tt.wantBody.Description {
//				t.Errorf("%s: Description want %q, got %q", tt.name, tt.wantBody.Description, got.Description)
//			}
//			if got.Type != tt.wantBody.Type {
//				t.Errorf("%s: Type want %q, got %q", tt.name, tt.wantBody.Type, got.Type)
//			}
//			if got.Month != tt.wantBody.Month {
//				t.Errorf("%s: Month want %d, got %d", tt.name, tt.wantBody.Month, got.Month)
//			}
//			if got.Level != tt.wantBody.Level {
//				t.Errorf("%s: Level want %d, got %d", tt.name, tt.wantBody.Level, got.Level)
//			}
//			if got.Language != tt.wantBody.Language {
//				t.Errorf("%s: Language want %q, got %q", tt.name, tt.wantBody.Language, got.Language)
//			}
//			if tt.wantBody.ReportPackage == nil {
//				if got.ReportPackage != nil {
//					t.Errorf("%s: expected ReportPackage to be nil", tt.name)
//				}
//			} else {
//				if got.ReportPackage == nil || *got.ReportPackage != *tt.wantBody.ReportPackage {
//					t.Errorf("%s: ReportPackage want %v, got %v", tt.name, *tt.wantBody.ReportPackage, got.ReportPackage)
//				}
//			}
//			if tt.wantBody.PaygatePackage == nil {
//				if got.PaygatePackage != nil {
//					t.Errorf("%s: expected PaygatePackage to be nil", tt.name)
//				}
//			} else {
//				if got.PaygatePackage == nil || *got.PaygatePackage != *tt.wantBody.PaygatePackage {
//					t.Errorf("%s: PaygatePackage want %v, got %v", tt.name, *tt.wantBody.PaygatePackage, got.PaygatePackage)
//				}
//			}
//		})
//	}
//}
//
//func TestRoleHandler_verifyCreate(t *testing.T) {
//	e := echo.New()
//	e.Validator = &CustomValidator{validator: validator.New()}
//
//	tests := []struct {
//		name         string
//		body         string
//		wantErr      bool
//		errMsgSubstr string
//	}{
//		{
//			name: "valid input mass type with all required fields",
//			body: `{
//				"role_id": "role123",
//				"description": "valid description",
//				"type": "mass",
//				"month": 1,
//				"level": 1,
//				"language": "en",
//				"report_package": true,
//				"paygate_package": "paygate123",
//				"paygate_package_name": "Premium Package",
//				"limit_account": 10,
//				"limit_ip_domain": 20,
//				"limit_product": 30,
//				"limit_alert": 5,
//				"limit_aliases": 15,
//				"permissions": ["read", "write"]
//			}`,
//			wantErr: false,
//		},
//		{
//			name: "mass type with empty paygate_package_name",
//			body: `{
//        "role_id": "role123",
//        "description": "desc",
//        "type": "mass",
//        "month": 1,
//        "level": 1,
//        "language": "en",
//        "report_package": true,
//        "paygate_package": "paygate123",
//        "paygate_package_name": "",
//        "limit_account": 10,
//        "limit_ip_domain": 20,
//        "limit_product": 30,
//        "limit_alert": 5,
//        "limit_aliases": 15,
//        "permissions": ["read", "write"]
//    }`,
//			wantErr:      true,
//			errMsgSubstr: "paygate is required for mass type",
//		},
//		{
//			name: "mass type with nil paygate_package_name",
//			body: `{
//        "role_id": "role123",
//        "description": "desc",
//        "type": "mass",
//        "month": 1,
//        "level": 1,
//        "language": "en",
//        "report_package": true,
//        "paygate_package": "paygate123",
//        "limit_account": 10,
//        "limit_ip_domain": 20,
//        "limit_product": 30,
//        "limit_alert": 5,
//        "limit_aliases": 15,
//        "permissions": ["read", "write"]
//    }`,
//			wantErr:      true,
//			errMsgSubstr: "paygate is required for mass type",
//		},
//		{
//			name: "mass type missing report_package",
//			body: `{
//				"role_id": "role123",
//				"description": "desc",
//				"type": "mass",
//				"month": 1,
//				"level": 1,
//				"language": "en",
//				"paygate_package": "paygate123",
//				"paygate_package_name": "Premium Package",
//				"limit_account": 10,
//				"limit_ip_domain": 20,
//				"limit_product": 30,
//				"limit_alert": 5,
//				"limit_aliases": 15,
//				"permissions": ["read", "write"]
//			}`,
//			wantErr:      true,
//			errMsgSubstr: "report_package is required for mass type",
//		},
//		{
//			name: "mass type missing paygate_package",
//			body: `{
//				"role_id": "role123",
//				"description": "desc",
//				"type": "mass",
//				"month": 1,
//				"level": 1,
//				"language": "en",
//				"report_package": true,
//				"paygate_package_name": "Premium Package",
//				"limit_account": 10,
//				"limit_ip_domain": 20,
//				"limit_product": 30,
//				"limit_alert": 5,
//				"limit_aliases": 15,
//				"permissions": ["read", "write"]
//			}`,
//			wantErr:      true,
//			errMsgSubstr: "paygate is required for mass type",
//		},
//		{
//			name: "non mass type no report and paygate required",
//			body: `{
//				"role_id": "role123",
//				"description": "desc",
//				"type": "enterprise",
//				"month": 1,
//				"level": 1,
//				"language": "en",
//				"limit_account": 10,
//				"limit_ip_domain": 20,
//				"limit_product": 30,
//				"limit_alert": 5,
//				"limit_aliases": 15,
//				"permissions": ["read", "write"]
//			}`,
//			wantErr: false,
//		},
//		{
//			name: "validate error missing required role_id",
//			body: `{
//				"description": "desc",
//				"type": "mass",
//				"month": 1,
//				"level": 1,
//				"language": "en",
//				"report_package": true,
//				"paygate_package": "paygate123",
//				"paygate_package_name": "Premium Package",
//				"limit_account": 10,
//				"limit_ip_domain": 20,
//				"limit_product": 30,
//				"limit_alert": 5,
//				"limit_aliases": 15,
//				"permissions": ["read", "write"]
//			}`,
//			wantErr:      true,
//			errMsgSubstr: "failed on the 'required' tag",
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
//			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
//			rec := httptest.NewRecorder()
//			c := e.NewContext(req, rec)
//			h := &RoleHandler{}
//			_, err := h.verifyCreate(c)
//			if tt.wantErr {
//				if err == nil {
//					t.Errorf("%s: expected error but got none", tt.name)
//				} else if !strings.Contains(err.Error(), tt.errMsgSubstr) {
//					t.Errorf("%s: expected error containing %q but got %v", tt.name, tt.errMsgSubstr, err)
//				}
//				return
//			}
//			if err != nil {
//				t.Errorf("%s: unexpected error: %v", tt.name, err)
//			}
//		})
//	}
//}

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
