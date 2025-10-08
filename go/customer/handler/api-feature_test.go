package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	mock_repo "gitlab.viettelcyber.com/ti-micro/ws-customer/mock/repo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.uber.org/mock/gomock"
)

func TestFeatureHandler_CreateFeature(t *testing.T) {
	tests := []struct {
		name            string
		requestBody     *model.RequestCreateFeature
		setupMock       func(mm *mock_repo.MockFeaturesRepository)
		expectedStatus  int
		expectedMessage string
	}{
		{
			name: "Invalid Request Body",
			requestBody: &model.RequestCreateFeature{
				Name: "",
			},
			setupMock:      func(mm *mock_repo.MockFeaturesRepository) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Successful Feature Creation",
			requestBody: &model.RequestCreateFeature{
				Name:          "name",
				Code:          "feature_code",
				Description:   "description",
				ParentFeature: "parent_code",
				Permissions:   []string{"read", "update"},
				Weight:        100,
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "feature_code").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)

				mm.EXPECT().
					GetByName(gomock.Any(), "parent_code").
					Return(&model.Feature{
						Code: "parent_code",
					}, nil).
					Times(1)

				mm.EXPECT().
					Store(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Feature Error",
			requestBody: &model.RequestCreateFeature{
				Name:          "name",
				Code:          "feature_code",
				Description:   "description",
				ParentFeature: "parent_code",
				Permissions:   []string{"read", "update"},
				Weight:        100,
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "feature_code").
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Feature Already Exists",
			requestBody: &model.RequestCreateFeature{
				Name:          "name",
				Code:          "feature_code",
				Description:   "description",
				ParentFeature: "parent_code",
				Permissions:   []string{"read", "update"},
				Weight:        100,
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "feature_code").
					Return(&model.Feature{
						Code: "feature_code",
					}, nil).
					Times(1)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Store Feature Fail",
			requestBody: &model.RequestCreateFeature{
				Name:          "name",
				Code:          "feature_code",
				Description:   "description",
				ParentFeature: "parent_code",
				Permissions:   []string{"read", "update"},
				Weight:        100,
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "feature_code").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)

				mm.EXPECT().
					GetByName(gomock.Any(), "parent_code").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Store Feature Error",
			requestBody: &model.RequestCreateFeature{
				Name:          "name",
				Code:          "feature_code",
				Description:   "description",
				ParentFeature: "parent_code",
				Permissions:   []string{"read", "update"},
				Weight:        100,
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "feature_code").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)

				mm.EXPECT().
					GetByName(gomock.Any(), "parent_code").
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Successful Feature Error",
			requestBody: &model.RequestCreateFeature{
				Name:          "name",
				Code:          "feature_code",
				Description:   "description",
				ParentFeature: "parent_code",
				Permissions:   []string{"read", "update"},
				Weight:        100,
			},
			setupMock: func(mm *mock_repo.MockFeaturesRepository) {
				mm.EXPECT().
					GetByName(gomock.Any(), "feature_code").
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)

				mm.EXPECT().
					GetByName(gomock.Any(), "parent_code").
					Return(&model.Feature{
						Code: "parent_code",
					}, nil).
					Times(1)

				mm.EXPECT().
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

			mockFeaturesRepo := mock_repo.NewMockFeaturesRepository(ctrl)
			mockAccountRepo := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccountRepo.EXPECT().Features().Return(mockFeaturesRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccountRepo).AnyTimes()

			tc.setupMock(mockFeaturesRepo)
			h := &FeatureHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}

			t.Logf("RequestBody: %+v", tc.requestBody)
			b, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/create", bytes.NewBuffer(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", "test_user")
			err := h.Create(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestFeatureHandler_GetAllFeature(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    *model.RequestFeatureList
		setupMock      func(mf *mock_repo.MockFeaturesRepository)
		expectedStatus int
		expectMessage  string
	}{
		{
			name: "Valid Request Body",
			requestBody: &model.RequestFeatureList{
				Size: -1,
			},
			setupMock:      func(mf *mock_repo.MockFeaturesRepository) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Get module successfully",
			requestBody: &model.RequestFeatureList{
				Sort: []string{"-name"},
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Feature{{ID: "r1", Code: "ROLE1"}}, nil).
					Times(1)

				mf.EXPECT().
					Count(gomock.Any(), gomock.Any()).
					Return(int64(10), nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "Get feature fail",
			requestBody: &model.RequestFeatureList{},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Get feature empty",
			requestBody: &model.RequestFeatureList{},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New(mg.NotFoundError)).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Count fail",
			requestBody: &model.RequestFeatureList{
				Sort: []string{"-name"},
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Feature{{ID: "r1", Code: "feat1"}}, nil).
					Times(1)

				mf.EXPECT().
					Count(gomock.Any(), gomock.Any()).
					Return(int64(0), errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Get feature by code",
			requestBody: &model.RequestFeatureList{
				FeatureCode: "feature_code",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().
					GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Feature{ID: "r1", Code: "feature_code", Ancestors: []string{"feature_code1"}}, nil).
					Times(1)

				mf.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Feature{{ID: "r1", Code: "ROLE1"}}, nil).
					Times(1)

				mf.EXPECT().
					Count(gomock.Any(), gomock.Any()).
					Return(int64(10), nil).
					Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Get feature by code error 500",
			requestBody: &model.RequestFeatureList{
				FeatureCode: "feature_code",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().
					GetByName(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("error")).
					Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Get feature by code error 400",
			requestBody: &model.RequestFeatureList{
				FeatureCode: "feature_code",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().
					GetByName(gomock.Any(), gomock.Any()).
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

			mockFeaturesRepo := mock_repo.NewMockFeaturesRepository(ctrl)
			mockAccount := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccount.EXPECT().Features().Return(mockFeaturesRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
			tc.setupMock(mockFeaturesRepo)

			h := &FeatureHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}

			jsonBody, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/list", bytes.NewBuffer(jsonBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := h.GetAllFeature(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestFeatureHandle_DetailFeature(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    *model.RequestCode
		setupMock      func(mm *mock_repo.MockFeaturesRepository)
		expectedStatus int
	}{
		{
			name: "Valid Request Body",
			requestBody: &model.RequestCode{
				ID: "",
			},
			setupMock:      func(mf *mock_repo.MockFeaturesRepository) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Get feature detail successfully",
			requestBody: &model.RequestCode{
				ID: "id1",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Feature{ID: "id1"}, nil).Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Get feature detail not found",
			requestBody: &model.RequestCode{
				ID: "id1",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(nil, errors.New(mg.NotFoundError)).Times(1)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "Get feature detail not found",
			requestBody: &model.RequestCode{
				ID: "id1",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("error")).Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockFeaturesRepo := mock_repo.NewMockFeaturesRepository(ctrl)
			mockAccount := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccount.EXPECT().Features().Return(mockFeaturesRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
			tc.setupMock(mockFeaturesRepo)
			h := &FeatureHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}
			jsonBody, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest(http.MethodGet, "/detail/:id", bytes.NewBuffer(jsonBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			err := h.DetailFeature(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestFeatureHandle_EditFeature(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    *model.RequestEditFeature
		setupMock      func(mf *mock_repo.MockFeaturesRepository)
		expectedStatus int
	}{
		{
			name:           "Valid Request Body",
			requestBody:    &model.RequestEditFeature{ID: ""},
			setupMock:      func(mf *mock_repo.MockFeaturesRepository) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "update success",
			requestBody: &model.RequestEditFeature{
				ID:            "id1",
				Name:          "feat1",
				Permissions:   []string{"read"},
				Description:   "des",
				Weight:        5,
				ParentFeature: "parent",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Feature{
						Code: "id1",
						Name: "name",
					}, nil).Times(1)

				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Feature{
						Code: "parent",
					}, nil).Times(1)

				mf.EXPECT().UpdateByID(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Times(1)

				mf.EXPECT().UpdateMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Update fail",
			requestBody: &model.RequestEditFeature{
				ID:            "id1",
				Name:          "feat1",
				Permissions:   []string{"read"},
				Description:   "des",
				Weight:        5,
				ParentFeature: "parent",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Feature{
						Code: "id1",
						Name: "name",
					}, nil).Times(1)

				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Feature{
						Code: "parent",
					}, nil).Times(1)

				mf.EXPECT().UpdateByID(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("error")).Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Update many fail",
			requestBody: &model.RequestEditFeature{
				ID:            "id1",
				Name:          "feat1",
				Permissions:   []string{"read"},
				Description:   "des",
				Weight:        5,
				ParentFeature: "parent",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Feature{
						Code: "id1",
						Name: "name",
					}, nil).Times(1)

				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Feature{
						Code: "parent",
					}, nil).Times(1)

				mf.EXPECT().UpdateByID(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Times(1)

				mf.EXPECT().UpdateMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("error")).Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Update not found",
			requestBody: &model.RequestEditFeature{
				ID:            "id1",
				Name:          "feat1",
				Permissions:   []string{"read"},
				Description:   "des",
				Weight:        5,
				ParentFeature: "parent",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(nil, errors.New(mg.NotFoundError)).Times(1)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "Update Error",
			requestBody: &model.RequestEditFeature{
				ID:            "id1",
				Name:          "feat1",
				Permissions:   []string{"read"},
				Description:   "des",
				Weight:        5,
				ParentFeature: "parent",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("error")).Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "update Parent fail",
			requestBody: &model.RequestEditFeature{
				ID:            "id1",
				Name:          "feat1",
				Permissions:   []string{"read"},
				Description:   "des",
				Weight:        5,
				ParentFeature: "parent",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Feature{
						Code: "id1",
						Name: "name",
					}, nil).Times(1)

				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("error")).Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "update Parent fail",
			requestBody: &model.RequestEditFeature{
				ID:            "id1",
				Name:          "feat1",
				Permissions:   []string{"read"},
				Description:   "des",
				Weight:        5,
				ParentFeature: "parent",
			},
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Feature{
						Code: "id1",
						Name: "name",
					}, nil).Times(1)

				mf.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("parent feature not found")).Times(1)
			},
			expectedStatus: http.StatusBadRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockFeaturesRepo := mock_repo.NewMockFeaturesRepository(ctrl)
			mockAccount := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)

			mockAccount.EXPECT().Features().Return(mockFeaturesRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
			tc.setupMock(mockFeaturesRepo)

			h := &FeatureHandler{mongo: mockMongo}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}

			jsonBody, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest(http.MethodPut, "/edit/:id", bytes.NewBuffer(jsonBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", "test_user")
			err := h.Edit(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestFeatureHandler_validateParentFeature(t *testing.T) {
	tests := []struct {
		name               string
		parentFeatureCode  string
		currentFeatureCode string
		currentParentID    string
		setupMock          func(mf *mock_repo.MockFeaturesRepository)
		wantErr            bool
		expectedErrMsg     string
	}{
		{
			name:               "parentFeatureCode là chính nó",
			parentFeatureCode:  "f1",
			currentFeatureCode: "f1",
			currentParentID:    "f2",
			setupMock:          func(mf *mock_repo.MockFeaturesRepository) {},
			wantErr:            true,
			expectedErrMsg:     "cannot be parent of itself",
		},
		{
			name:               "parentFeatureCode không tồn tại",
			parentFeatureCode:  "f2",
			currentFeatureCode: "f1",
			currentParentID:    "f3",
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), "f2").
					Return(nil, errors.New(mg.NotFoundError)).Times(1)
			},
			wantErr:        true,
			expectedErrMsg: "parent feature not found",
		},
		{
			name:               "parentFeatureCode tồn tại thành công",
			parentFeatureCode:  "f4",
			currentFeatureCode: "f1",
			currentParentID:    "a2",
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), "f4").
					Return(&model.Feature{ID: "id4", Code: "f4"}, nil).Times(1)
			},
			wantErr:        false,
			expectedErrMsg: "",
		},
		{
			name:               "parentFeatureCode lỗi NotFoundError",
			parentFeatureCode:  "f8",
			currentFeatureCode: "f1",
			currentParentID:    "f1",
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), "f8").
					Return(nil, errors.New(mg.NotFoundError)).Times(1)
			},
			wantErr:        true,
			expectedErrMsg: "parent feature not found",
		},
		{
			name:               "parentFeatureCode repo trả error khác",
			parentFeatureCode:  "f9",
			currentFeatureCode: "f1",
			currentParentID:    "f1",
			setupMock: func(mf *mock_repo.MockFeaturesRepository) {
				mf.EXPECT().GetByName(gomock.Any(), "f9").
					Return(nil, errors.New("mongo connection lost")).Times(1)
			},
			wantErr:        true,
			expectedErrMsg: "mongo connection lost",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockFeaturesRepo := mock_repo.NewMockFeaturesRepository(ctrl)
			mockAccount := mock_repo.NewMockAccountRepository(ctrl)
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
			mockAccount.EXPECT().Features().Return(mockFeaturesRepo).AnyTimes()
			mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
			tc.setupMock(mockFeaturesRepo)

			h := &FeatureHandler{mongo: mockMongo}

			res, err := h.validateParentFeature(
				tc.parentFeatureCode,
				tc.currentFeatureCode,
				tc.currentParentID,
			)

			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, tc.parentFeatureCode, res.Code)
			}
		})
	}
}

func TestBuildFeatureTree(t *testing.T) {
	tests := []struct {
		name     string
		modules  []*model.FeatureWithPermissions
		expected []*model.FeatureWithPermissions
	}{
		{
			name: "single root module",
			modules: []*model.FeatureWithPermissions{
				{
					Feature: model.Feature{
						ID:       "1",
						Name:     "Root",
						ParentID: "",
					},
					Permissions: []*model.PermissionsResponse{
						{ID: "perm1", PermissionID: "read", Description: "Read", ModifiedTime: 123},
					},
				},
			},
			expected: []*model.FeatureWithPermissions{
				{
					Feature: model.Feature{
						ID:       "1",
						Name:     "Root",
						ParentID: "",
					},
					Children: nil,
					Permissions: []*model.PermissionsResponse{
						{ID: "perm1", PermissionID: "read", Description: "Read", ModifiedTime: 123},
					},
				},
			},
		},
		{
			name: "parent with children",
			modules: []*model.FeatureWithPermissions{
				{
					Feature: model.Feature{ID: "1", Name: "Parent", ParentID: ""},
				},
				{
					Feature: model.Feature{ID: "2", Name: "Child1", ParentID: "1"},
				},
				{
					Feature: model.Feature{ID: "3", Name: "Child2", ParentID: "1"},
				},
			},
			expected: []*model.FeatureWithPermissions{
				{
					Feature: model.Feature{ID: "1", Name: "Parent", ParentID: ""},
					Children: []*model.FeatureWithPermissions{
						{Feature: model.Feature{ID: "2", Name: "Child1", ParentID: "1"}, Children: nil},
						{Feature: model.Feature{ID: "3", Name: "Child2", ParentID: "1"}, Children: nil},
					},
				},
			},
		},
		{
			name: "multi-level hierarchy",
			modules: []*model.FeatureWithPermissions{
				{Feature: model.Feature{ID: "1", Name: "Root", ParentID: ""}},
				{Feature: model.Feature{ID: "2", Name: "Level1", ParentID: "1"}},
				{Feature: model.Feature{ID: "3", Name: "Level2", ParentID: "2"}},
			},
			expected: []*model.FeatureWithPermissions{
				{
					Feature: model.Feature{ID: "1", Name: "Root", ParentID: ""},
					Children: []*model.FeatureWithPermissions{
						{
							Feature: model.Feature{ID: "2", Name: "Level1", ParentID: "1"},
							Children: []*model.FeatureWithPermissions{
								{Feature: model.Feature{ID: "3", Name: "Level2", ParentID: "2"}, Children: nil},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildFeatureTree(tt.modules)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("BuildFeatureTree() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func Test_areAncestorsEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{
			name: "equal slices",
			a:    []string{"A", "B", "C"},
			b:    []string{"A", "B", "C"},
			want: true,
		},
		{
			name: "different lengths",
			a:    []string{"A", "B"},
			b:    []string{"A", "B", "C"},
			want: false,
		},
		{
			name: "same length but different values",
			a:    []string{"A", "B", "C"},
			b:    []string{"A", "X", "C"},
			want: false,
		},
		{
			name: "both empty",
			a:    []string{},
			b:    []string{},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := areAncestorsEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("areAncestorsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}
