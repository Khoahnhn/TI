package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	mock_repo "gitlab.viettelcyber.com/ti-micro/ws-customer/mock/repo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.uber.org/mock/gomock"
)

func TestOrganizationHandler_SearchOrganizations(t *testing.T) {
	e := echo.New()
	v := validator.New()
	_ = v.RegisterValidation("code", codeValidator)
	e.Validator = &CustomValidator{validator: v}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger, _ := pencil.New("org-search", pencil.DebugLevel, true, os.Stdout)

	err := errors.New("foo")
	tests := []struct {
		name       string
		h          *OrganizationHandler
		body       any
		wantStatus int
	}{
		{
			name: "bind_fail",
			h: func() *OrganizationHandler {
				return &OrganizationHandler{}
			}(),
			body:       "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "agg_fail",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()

				mockGroupUser.EXPECT().
					RunAggPipeline(gomock.Any(), gomock.Any(), gomock.Any()).
					Times(1).Return(err)
				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body:       model.RequestSearchOrganization{},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "happy_case",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()

				mockGroupUser.EXPECT().
					RunAggPipeline(gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_ context.Context, _ []*bson.M, result any) {
						resultPtr := result.(*[]*model.OrganizationSearchData)
						*resultPtr = []*model.OrganizationSearchData{
							{
								Organization: model.Organization{},
								Package:      model.Role{},
							},
						}
					}).
					Times(1).Return(nil)
				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestSearchOrganization{
				EffectiveInterval: model.RequestTimeInterval{
					StartTime: 1,
					EndTime:   2,
				},
				ExpiredInterval: model.RequestTimeInterval{
					StartTime: 1,
					EndTime:   2,
				},
				SearchTerm:     "bar",
				Package:        []string{"foo"},
				IndustrySector: []string{"bar"},
				StatusActive:   []bool{true},
				TypeIsMass:     []bool{false},
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/op/organization/v2/search", bytes.NewReader(bodyBytes))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", "tester")
			tt.h.logger = logger
			if err := tt.h.SearchOrganizations(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestOrganizationHandler_ListOrganizations(t *testing.T) {
	e := echo.New()
	v := validator.New()
	_ = v.RegisterValidation("code", codeValidator)
	e.Validator = &CustomValidator{validator: v}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger, _ := pencil.New("org-search", pencil.DebugLevel, true, os.Stdout)

	err := errors.New("foo")
	tests := []struct {
		name       string
		h          *OrganizationHandler
		body       any
		wantStatus int
	}{
		{
			name: "query_fail",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()

				mockGroupUser.EXPECT().
					FindAllOrgs(gomock.Any(), gomock.Any(), gomock.Any()).
					Times(1).Return(nil, err)
				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body:       model.RequestSearchOrganization{},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "happy_case",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()

				mockGroupUser.EXPECT().
					FindAllOrgs(gomock.Any(), gomock.Any(), gomock.Any()).
					Times(1).Return(nil, nil)
				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body:       model.RequestSearchOrganization{},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/op/organization/v2/list", bytes.NewReader([]byte{}))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			tt.h.logger = logger
			if err := tt.h.ListOrganizations(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestOrganizationHandler_ListIndustry(t *testing.T) {
	e := echo.New()
	tests := []struct {
		name       string
		h          *OrganizationHandler
		wantStatus int
	}{
		{
			name:       "happy_case",
			h:          &OrganizationHandler{},
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/op/organization/v2/industry/list", bytes.NewReader([]byte{}))
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			tt.h.logger = logger
			if err := tt.h.ListIndustry(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestOrganizationHandler_Statistics(t *testing.T) {
	e := echo.New()
	v := validator.New()
	_ = v.RegisterValidation("code", codeValidator)
	e.Validator = &CustomValidator{validator: v}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger, _ := pencil.New("org-search", pencil.DebugLevel, true, os.Stdout)

	err := errors.New("foo")
	tests := []struct {
		name       string
		h          *OrganizationHandler
		body       any
		wantStatus int
	}{
		{
			name: "bind_fail",
			h: func() *OrganizationHandler {
				return &OrganizationHandler{}
			}(),
			body:       "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "query_fail",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()

				mockGroupUser.EXPECT().RunAggPipeline(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(err).Times(1)
				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body:       model.RequestSearchOrganization{},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "no_data",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()

				mockGroupUser.EXPECT().RunAggPipeline(gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_ context.Context, _ []*bson.M, result any) {
						resultPtr := result.(*[]*model.OrganizationStats)
						*resultPtr = []*model.OrganizationStats{}
					}).Return(nil).Times(1)
				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body:       model.RequestSearchOrganization{},
			wantStatus: http.StatusOK,
		},
		{
			name: "happy_case",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()

				mockGroupUser.EXPECT().RunAggPipeline(gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_ context.Context, _ []*bson.M, result any) {
						resultPtr := result.(*[]*model.OrganizationStats)
						*resultPtr = []*model.OrganizationStats{{
							Total:       10,
							ActiveCount: 6,
							MassCount:   9,
							Industries:  []string{"foo", "other"},
							Packages:    []string{"bar"},
						}}
					}).Return(nil).Times(1)
				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body:       model.RequestSearchOrganization{},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/op/organization/v2/statistics", bytes.NewReader(bodyBytes))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			tt.h.logger = logger
			if err := tt.h.Statistics(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestOrganizationHandler_DetailOrganization(t *testing.T) {
	e := echo.New()
	v := validator.New()
	_ = v.RegisterValidation("code", codeValidator)
	e.Validator = &CustomValidator{validator: v}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger, _ := pencil.New("org-search", pencil.DebugLevel, true, os.Stdout)

	err := errors.New("foo")
	tests := []struct {
		name       string
		h          *OrganizationHandler
		id         string
		wantStatus int
	}{
		{
			name: "query_failed",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()

				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, err).Times(1)
				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			id:         "1234",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "not_found",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()

				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, nil).Times(1)
				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			id:         "1234",
			wantStatus: http.StatusNotFound,
		},
		{
			name: "happy_case",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()

				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{}, nil).Times(1)
				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			id:         "1234",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/op/organization/v2/"+tt.id, bytes.NewReader([]byte{}))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tt.id)
			tt.h.logger = logger
			if err := tt.h.DetailOrganization(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestOrganizationHandler_CreateOrganizations(t *testing.T) {
	e := echo.New()
	v := validator.New()
	_ = v.RegisterValidation("code", codeValidator)
	e.Validator = &CustomValidator{validator: v}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger, _ := pencil.New("org-search", pencil.DebugLevel, true, os.Stdout)

	err := errors.New("foo")
	tests := []struct {
		name       string
		h          *OrganizationHandler
		body       any
		username   string
		wantStatus int
	}{
		{
			name:       "bind_fail",
			h:          &OrganizationHandler{},
			body:       "foo",
			username:   "bar",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "empty_username",
			h:    &OrganizationHandler{},
			body: model.RequestStoreOrganization{
				TenantId:  "1234567",
				ParentId:  "foo",
				PackageId: "bar",
				Industry:  []string{"foo"},
			},
			username:   "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid_industry",
			h:    &OrganizationHandler{},
			body: model.RequestStoreOrganization{
				TenantId:  "1234567",
				ParentId:  "foo",
				PackageId: "bar",
				Industry:  []string{"bar"},
			},
			username:   "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid_lang",
			h:    &OrganizationHandler{},
			body: model.RequestStoreOrganization{
				TenantId:  "1234567",
				ParentId:  "foo",
				PackageId: "bar",
				Industry:  []string{"other"},
				Lang:      defs.Language("us"),
			},
			username:   "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid_name",
			h:    &OrganizationHandler{},
			body: model.RequestStoreOrganization{
				TenantId:  "1234567",
				ParentId:  "foo",
				PackageId: "bar",
				Industry:  []string{"other"},
				Lang:      defs.Language("vi"),
				Name:      "",
			},
			username:   "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid_expired_time",
			h:    &OrganizationHandler{},
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 2,
				ExpiredTime:   1,
			},
			username:   "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "query_role_failed",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(nil, err).Times(1)
				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "query_parent_failed",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()

				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, err).Times(1)
				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "query_existed_failed",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()

				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true}, nil).Times(1)
				mockGroupUser.EXPECT().Get(gomock.Any(), gomock.Any()).
					Return(nil, err).Times(1)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "query_existed_org",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()

				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true}, nil).Times(1)
				mockGroupUser.EXPECT().Get(gomock.Any(), gomock.Any()).
					Return(&model.GroupUser{}, nil).Times(1)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "insert_fail",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()

				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true, Multilang: model.OrganizationMultilang{Vi: &model.OrganizationInfo{Name: "test"}}}, nil).
					Times(1)
				mockGroupUser.EXPECT().Get(gomock.Any(), gomock.Any()).
					Return(nil, nil).Times(1)
				mockGroupUser.EXPECT().InsertOrg(gomock.Any(), gomock.Any()).
					Return(err).Times(1)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "insert_history_fail",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true, Multilang: model.OrganizationMultilang{Vi: &model.OrganizationInfo{Name: "test"}}}, nil).
					Times(1)
				mockGroupUser.EXPECT().Get(gomock.Any(), gomock.Any()).
					Return(nil, nil).Times(1)
				mockGroupUser.EXPECT().InsertOrg(gomock.Any(), gomock.Any()).
					Return(nil).Times(1)

				mockOrgHistory.EXPECT().Insert(gomock.Any(), gomock.Any()).
					Return(err).Times(1)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "happy_case",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true, Multilang: model.OrganizationMultilang{Vi: &model.OrganizationInfo{Name: "test"}}}, nil).
					Times(1)
				mockGroupUser.EXPECT().Get(gomock.Any(), gomock.Any()).
					Return(nil, nil).Times(1)
				mockGroupUser.EXPECT().InsertOrg(gomock.Any(), gomock.Any()).
					Return(nil).Times(1)

				mockOrgHistory.EXPECT().Insert(gomock.Any(), gomock.Any()).
					Return(nil).Times(1)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{Mass: true}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/op/organization/v2/create", bytes.NewReader(bodyBytes))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", tt.name)
			tt.h.logger = logger
			if err := tt.h.CreateOrganizations(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestOrganizationHandler_UpdateOrganization(t *testing.T) {
	e := echo.New()
	v := validator.New()
	_ = v.RegisterValidation("code", codeValidator)
	e.Validator = &CustomValidator{validator: v}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger, _ := pencil.New("org-search", pencil.DebugLevel, false, os.Stdout)

	err := errors.New("foo")
	tests := []struct {
		name       string
		h          *OrganizationHandler
		body       any
		username   string
		wantStatus int
	}{
		{
			name:       "bind_fail",
			h:          &OrganizationHandler{},
			body:       "foo",
			username:   "bar",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "validate_fail",
			h:    &OrganizationHandler{},
			body: model.RequestStoreOrganization{
				TenantId:  "1234567",
				ParentId:  "foo",
				PackageId: "bar",
				Industry:  []string{"foo"},
			},
			username:   "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "query_original_fail",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				// Parent
				parentOrgCall := mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true, Multilang: model.OrganizationMultilang{Vi: &model.OrganizationInfo{Name: "test"}}}, nil).
					Times(1)
				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, err).Times(1).After(parentOrgCall)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "original_not_found",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				parentCall := mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true, Multilang: model.OrganizationMultilang{Vi: &model.OrganizationInfo{Name: "test"}}}, nil).
					Times(1)
				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, nil).Times(1).After(parentCall)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "update_root",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				parentCall := mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true, Multilang: model.OrganizationMultilang{Vi: &model.OrganizationInfo{Name: "test"}}}, nil).
					Times(1)
				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{TenantId: "root"}, nil).Times(1).After(parentCall)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "update_root",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				parentCall := mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true, Multilang: model.OrganizationMultilang{Vi: &model.OrganizationInfo{Name: "test"}}}, nil).
					Times(1)
				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{TenantId: "root"}, nil).Times(1).After(parentCall)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "id_mismatch",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				parentCall := mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true, Multilang: model.OrganizationMultilang{Vi: &model.OrganizationInfo{Name: "test"}}}, nil).
					Times(1)
				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{TenantId: "123456"}, nil).Times(1).After(parentCall)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "cycle_parent",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				parentCall := mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{
						Active:    true,
						Ancestors: []string{"1", "1234567"},
						Multilang: model.OrganizationMultilang{Vi: &model.OrganizationInfo{Name: "test"}},
					}, nil).
					Times(1)
				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{TenantId: "1234567"}, nil).Times(1).After(parentCall)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "update_failed",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true, Multilang: model.OrganizationMultilang{Vi: &model.OrganizationInfo{Name: "test"}}}, nil).
					Times(1)
				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{TenantId: "1234567"}, nil).Times(1)
				mockGroupUser.EXPECT().UpdateOrg(gomock.Any(), gomock.Any()).
					Return(err).Times(1)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "happy_case",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{Active: true, Multilang: model.OrganizationMultilang{Vi: &model.OrganizationInfo{Name: "test"}}}, nil).
					Times(1)
				mockGroupUser.EXPECT().GetOrg(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.Organization{TenantId: "1234567"}, nil).Times(1)
				mockGroupUser.EXPECT().UpdateOrg(gomock.Any(), gomock.Any()).
					Return(nil).Times(1)
				mockGroupUser.EXPECT().UpdateMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Times(1)

				mockOrgHistory.EXPECT().Insert(gomock.Any(), gomock.Any()).
					Return(nil).Times(1)

				mockRole.EXPECT().GetByName(gomock.Any(), gomock.Any()).
					Return(&model.Role{Mass: true}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestStoreOrganization{
				TenantId:      "1234567",
				ParentId:      "foo",
				PackageId:     "bar",
				Industry:      []string{"other"},
				Lang:          defs.Language("vi"),
				Name:          "foo",
				EffectiveTime: 1,
				ExpiredTime:   2,
			},
			username:   "foo",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/op/organization/v2/create", bytes.NewReader(bodyBytes))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", tt.name)
			tt.h.logger = logger
			if err := tt.h.UpdateOrganization(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestOrganizationHandler_ChangeStatus(t *testing.T) {
	e := echo.New()
	v := validator.New()
	_ = v.RegisterValidation("code", codeValidator)
	e.Validator = &CustomValidator{validator: v}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger, _ := pencil.New("org-search", pencil.DebugLevel, false, os.Stdout)

	err := errors.New("foo")
	tests := []struct {
		name       string
		h          *OrganizationHandler
		body       any
		username   string
		wantStatus int
	}{
		{
			name:       "bind_fail",
			h:          &OrganizationHandler{},
			body:       "foo",
			username:   "bar",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "fail_find_org",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				mockGroupUser.EXPECT().FindAllOrgs(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, err)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestOrganizationChangeStatus{
				Ids: []string{"123456"},
			},
			username:   "foo",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "no_matched_org",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				mockGroupUser.EXPECT().FindAllOrgs(gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Organization{
						{TenantId: "root"},
					}, nil)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestOrganizationChangeStatus{
				Ids: []string{"123456"},
			},
			username:   "foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "failed_update",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockGroupUserV2 := mock_repo.NewMockGroupUserRepositoryV2(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()
				mockAccount.EXPECT().GroupUserV2().Return(mockGroupUserV2).AnyTimes()

				mockGroupUser.EXPECT().FindAllOrgs(gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Organization{
						{TenantId: "123456", Active: true},
					}, nil)

				mockGroupUserV2.EXPECT().BulkUpdateById(gomock.Any(), gomock.Any()).
					Return(err)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestOrganizationChangeStatus{
				Ids:    []string{"123456"},
				Active: false,
			},
			username:   "foo",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "failed_insert_history",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockGroupUserV2 := mock_repo.NewMockGroupUserRepositoryV2(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()
				mockAccount.EXPECT().GroupUserV2().Return(mockGroupUserV2).AnyTimes()

				mockGroupUser.EXPECT().FindAllOrgs(gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Organization{
						{TenantId: "123456", Active: true},
					}, nil)

				mockGroupUserV2.EXPECT().BulkUpdateById(gomock.Any(), gomock.Any()).
					Return(nil)

				mockOrgHistory.EXPECT().InsertMany(gomock.Any(), gomock.Any()).
					Return(err)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestOrganizationChangeStatus{
				Ids:    []string{"123456"},
				Active: false,
			},
			username:   "foo",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "happy_case_inactive",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockGroupUserV2 := mock_repo.NewMockGroupUserRepositoryV2(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()
				mockAccount.EXPECT().GroupUserV2().Return(mockGroupUserV2).AnyTimes()

				mockGroupUser.EXPECT().FindAllOrgs(gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Organization{
						{TenantId: "123456", Active: true},
					}, nil)

				mockGroupUserV2.EXPECT().BulkUpdateById(gomock.Any(), gomock.Any()).
					Return(nil)

				mockOrgHistory.EXPECT().InsertMany(gomock.Any(), gomock.Any()).
					Return(nil)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestOrganizationChangeStatus{
				Ids:    []string{"123456"},
				Active: false,
			},
			username:   "foo",
			wantStatus: http.StatusOK,
		},
		{
			name: "fail_get_roles",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockGroupUserV2 := mock_repo.NewMockGroupUserRepositoryV2(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()
				mockAccount.EXPECT().GroupUserV2().Return(mockGroupUserV2).AnyTimes()

				mockGroupUser.EXPECT().FindAllOrgs(gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Organization{
						{TenantId: "123456", Active: true},
					}, nil)

				mockRole.EXPECT().FindAll(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, err).Times(1)

				// mockGroupUserV2.EXPECT().BulkUpdateById(gomock.Any(), gomock.Any()).
				// 	Return(nil)

				// mockOrgHistory.EXPECT().InsertMany(gomock.Any(), gomock.Any()).
				// 	Return(nil)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestOrganizationChangeStatus{
				Ids:        []string{"123456"},
				Active:     true,
				UpdateTime: true,
			},
			username:   "foo",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "happy_case_active",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockGroupUser := mock_repo.NewMockGroupUserRepository(ctrl)
				mockGroupUserV2 := mock_repo.NewMockGroupUserRepositoryV2(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockRole := mock_repo.NewMockRolesRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().GroupUser().Return(mockGroupUser).AnyTimes()
				mockAccount.EXPECT().Roles().Return(mockRole).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()
				mockAccount.EXPECT().GroupUserV2().Return(mockGroupUserV2).AnyTimes()

				mockGroupUser.EXPECT().FindAllOrgs(gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Organization{
						{TenantId: "123456", Active: false, Role: "role"},
					}, nil)

				mockRole.EXPECT().FindAll(gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.Role{{
						RoleID: "role",
						Month:  2,
					}}, nil).Times(1)

				mockGroupUserV2.EXPECT().BulkUpdateById(gomock.Any(), gomock.Any()).
					Return(nil)

				mockOrgHistory.EXPECT().InsertMany(gomock.Any(), gomock.Any()).
					Return(nil)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestOrganizationChangeStatus{
				Ids:        []string{"123456"},
				Active:     true,
				UpdateTime: true,
			},
			username:   "foo",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/op/organization/v2/create", bytes.NewReader(bodyBytes))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", tt.name)
			tt.h.logger = logger
			if err := tt.h.ChangeStatus(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestOrganizationHandler_GetHistories(t *testing.T) {
	e := echo.New()
	v := validator.New()
	_ = v.RegisterValidation("code", codeValidator)
	e.Validator = &CustomValidator{validator: v}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger, _ := pencil.New("org-search", pencil.DebugLevel, false, os.Stdout)

	err := errors.New("foo")
	tests := []struct {
		name       string
		h          *OrganizationHandler
		body       any
		orgId      string
		wantStatus int
	}{
		{
			name:       "bind_fail",
			h:          &OrganizationHandler{},
			body:       "foo",
			orgId:      "1234",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "fail_get_history",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				mockOrgHistory.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, err).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body:       model.RequestOrganizationHistories{},
			orgId:      "1234",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "happy_case",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				mockOrgHistory.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.OrganizationHistory{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			body: model.RequestOrganizationHistories{
				Time: model.RequestTimeInterval{
					StartTime: 1,
					EndTime:   2,
				},
				Event: "create",
			},
			orgId:      "1234",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/op/organization/v2/create", bytes.NewReader(bodyBytes))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("org_id")
			c.SetParamValues(tt.orgId)
			tt.h.logger = logger
			if err := tt.h.GetHistories(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestOrganizationHandler_GetHistoryDetail(t *testing.T) {
	e := echo.New()
	v := validator.New()
	_ = v.RegisterValidation("code", codeValidator)
	e.Validator = &CustomValidator{validator: v}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger, _ := pencil.New("org-search", pencil.DebugLevel, false, os.Stdout)

	err := errors.New("foo")
	tests := []struct {
		name       string
		h          *OrganizationHandler
		id         string
		wantStatus int
	}{
		{
			name: "fail_get_history",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				mockOrgHistory.EXPECT().Get(gomock.Any(), gomock.Any()).
					Return(nil, err).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			id:         "1234",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "no_record",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				mockOrgHistory.EXPECT().Get(gomock.Any(), gomock.Any()).
					Return(nil, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			id:         "1234",
			wantStatus: http.StatusNotFound,
		},
		{
			name: "happy_case",
			h: func() *OrganizationHandler {
				mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
				mockOrgHistory := mock_repo.NewMockOrganizationHistoryRepo(ctrl)
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)

				mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
				mockAccount.EXPECT().OrgHistory().Return(mockOrgHistory).AnyTimes()

				mockOrgHistory.EXPECT().Get(gomock.Any(), gomock.Any()).
					Return(&model.OrganizationHistory{}, nil).Times(1)

				return &OrganizationHandler{
					mongo: mockMongo,
				}
			}(),
			id:         "1234",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/op/organization/v2/create", bytes.NewReader([]byte{}))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tt.id)
			tt.h.logger = logger
			if err := tt.h.GetHistoryDetail(c); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}
