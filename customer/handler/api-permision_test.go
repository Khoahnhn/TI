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
	"go.uber.org/mock/gomock"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPermissionHandler_GetPermissions(t *testing.T) {
	tests := []struct {
		name            string
		requestBody     *model.RequestGetPermissions
		setupMock       func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository)
		expectedStatus  int
		expectedMessage string
	}{
		{
			name: "Invalid Request Body",
			requestBody: &model.RequestGetPermissions{
				Size: -1,
			},
			setupMock:      func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Get Permissions",
			requestBody: &model.RequestGetPermissions{
				Keyword:  "keyword",
				Module:   "module",
				IsModule: false,
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					FindMany(gomock.Any(), gomock.Any()).
					Return([]*model.Feature{
						{ID: "ID", Name: "Module"},
					}, nil).
					Times(1)

				mp.EXPECT().
					Aggregate(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Get Permissions",
			requestBody: &model.RequestGetPermissions{
				Keyword:  "keyword",
				Module:   "module",
				IsModule: false,
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					FindMany(gomock.Any(), gomock.Any()).
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "Get Permissions",
			requestBody: &model.RequestGetPermissions{
				Keyword:  "keyword",
				Module:   "module",
				IsModule: false,
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					FindMany(gomock.Any(), gomock.Any()).
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

			mockModulesRepo := mock_repo.NewMockFeaturesRepository(ctrl)
			mockPermissionsRepo := mock_repo.NewMockPermissionsRepository(ctrl)
			mockAccountRepo := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccountRepo.EXPECT().Features().Return(mockModulesRepo).AnyTimes()
			mockAccountRepo.EXPECT().Permissions().Return(mockPermissionsRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccountRepo).AnyTimes()

			tc.setupMock(mockModulesRepo, mockPermissionsRepo)
			h := &PermissionHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}

			t.Logf("RequestBody: %+v", tc.requestBody)
			b, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/list", bytes.NewBuffer(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", "test_user")
			err := h.GetPermissions(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestPermissionHandler_ChangeModule(t *testing.T) {
	tests := []struct {
		name            string
		requestBody     *model.RequestUpdateModule
		setupMock       func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository)
		expectedStatus  int
		expectedMessage string
	}{
		{
			name:           "Invalid Request Body",
			requestBody:    &model.RequestUpdateModule{},
			setupMock:      func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Change successes",
			requestBody: &model.RequestUpdateModule{
				IDs:       []string{"id1", "id2"},
				NewModule: "module 1",
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "module 1").
					Return(&model.Feature{ID: "id"}, nil).
					Times(1)

				mp.EXPECT().
					GetByPermissionID(gomock.Any(), []string{"id1", "id2"}, int64(0), int64(2)).
					Return([]*model.Permissions{
						{ID: "id1"},
						{ID: "id2"},
					}, nil).
					Times(1)

				mp.EXPECT().
					UpdateFeature(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "new module not found",
			requestBody: &model.RequestUpdateModule{
				NewModule: "id1",
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "id1").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "new module error",
			requestBody: &model.RequestUpdateModule{
				NewModule: "id1",
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "id1").
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "permission error",
			requestBody: &model.RequestUpdateModule{
				NewModule: "module",
				IDs:       []string{"id1"},
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "module").
					Return(&model.Feature{ID: "module"}, nil).
					Times(1)

				mp.EXPECT().
					GetByPermissionID(gomock.Any(), []string{"id1"}, int64(0), int64(1)).
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "permission valid",
			requestBody: &model.RequestUpdateModule{
				NewModule: "module",
				IDs:       []string{"id1", "id valid"},
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "module").
					Return(&model.Feature{ID: "module"}, nil).
					Times(1)

				mp.EXPECT().
					GetByPermissionID(gomock.Any(), []string{"id1", "id valid"}, int64(0), int64(2)).
					Return([]*model.Permissions{
						{ID: "id1"},
					}, nil).
					Times(1)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Change fail",
			requestBody: &model.RequestUpdateModule{
				IDs:       []string{"id1", "id2"},
				NewModule: "module 1",
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "module 1").
					Return(&model.Feature{ID: "id"}, nil).
					Times(1)

				mp.EXPECT().
					GetByPermissionID(gomock.Any(), []string{"id1", "id2"}, int64(0), int64(2)).
					Return([]*model.Permissions{
						{ID: "id1"},
						{ID: "id2"},
					}, nil).
					Times(1)

				mp.EXPECT().
					UpdateFeature(gomock.Any(), gomock.Any()).
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

			mockModulesRepo := mock_repo.NewMockFeaturesRepository(ctrl)
			mockPermissionsRepo := mock_repo.NewMockPermissionsRepository(ctrl)
			mockAccountRepo := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccountRepo.EXPECT().Features().Return(mockModulesRepo).AnyTimes()
			mockAccountRepo.EXPECT().Permissions().Return(mockPermissionsRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccountRepo).AnyTimes()

			tc.setupMock(mockModulesRepo, mockPermissionsRepo)
			h := &PermissionHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}

			t.Logf("RequestBody: %+v", tc.requestBody)
			b, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/change-module", bytes.NewBuffer(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", "test_user")
			err := h.ChangeModule(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestPermissionHandler(t *testing.T) {
	tests := []struct {
		name            string
		requestBody     *model.RequestUpdatePermission
		setupMock       func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository)
		expectedStatus  int
		expectedMessage string
	}{
		{
			name: "Invalid Request body",
			requestBody: &model.RequestUpdatePermission{
				ID:          "id1",
				Description: "aa",
			},
			setupMock:      func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Update permission",
			requestBody: &model.RequestUpdatePermission{
				ID:          "id1",
				Description: "aa",
				Module:      "module",
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "module").
					Return(&model.Feature{ID: "module"}, nil).
					Times(1)

				mp.EXPECT().
					UpdateByID(gomock.Any(), "id1", gomock.Any()).
					Return(nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Update permission",
			requestBody: &model.RequestUpdatePermission{
				ID:          "id1",
				Description: "aa",
				Module:      "module",
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "module").
					Return(&model.Feature{ID: "module"}, nil).
					Times(1)

				mp.EXPECT().
					UpdateByID(gomock.Any(), "id1", gomock.Any()).
					Return(errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Module not found",
			requestBody: &model.RequestUpdatePermission{
				ID:          "id1",
				Description: "aa",
				Module:      "module",
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "module").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "Module error",
			requestBody: &model.RequestUpdatePermission{
				ID:          "id1",
				Description: "aa",
				Module:      "module",
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository, mp *mock_repo.MockPermissionsRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "module").
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

			mockModulesRepo := mock_repo.NewMockFeaturesRepository(ctrl)
			mockPermissionsRepo := mock_repo.NewMockPermissionsRepository(ctrl)
			mockAccountRepo := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccountRepo.EXPECT().Features().Return(mockModulesRepo).AnyTimes()
			mockAccountRepo.EXPECT().Permissions().Return(mockPermissionsRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccountRepo).AnyTimes()

			tc.setupMock(mockModulesRepo, mockPermissionsRepo)
			h := &PermissionHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}
			t.Logf("RequestBody: %+v", tc.requestBody)
			b, _ := json.Marshal(tc.requestBody)

			req := httptest.NewRequest(http.MethodPost, "/update/:id", bytes.NewBuffer(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			err := h.UpdatePermission(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}
