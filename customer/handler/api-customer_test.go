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

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	mock_repo "gitlab.viettelcyber.com/ti-micro/ws-customer/mock/repo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.uber.org/mock/gomock"
)

var (
	mockRole = model.Role{ID: "xxxxx", RoleID: "admin"}
)

func TestCustomerHandler_searchEasmOrganization(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type fields struct {
		roleRepo mongo.RolesRepository
	}

	type args struct {
		req model.RequestCustomerOrganizationSearch
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy case",
			args: args{
				req: model.RequestCustomerOrganizationSearch{IsEasm: true},
			},
			fields: func() fields {
				mockRoleRepo := mock_repo.NewMockRolesRepository(ctrl)
				mockRoleRepo.EXPECT().FindAll(gomock.Any(), gomock.Any(), gomock.Any()).Return([]*model.Role{&mockRole}, nil).AnyTimes()
				return fields{
					roleRepo: mockRoleRepo,
				}
			}(),
			wantErr: false,
		},
		{
			name: "happy case - false is easm",
			args: args{
				req: model.RequestCustomerOrganizationSearch{},
			},
			fields: func() fields {
				return fields{}
			}(),
			wantErr: false,
		},
		{
			name: "happy case - empty roles",
			args: args{
				req: model.RequestCustomerOrganizationSearch{IsEasm: true},
			},
			fields: func() fields {
				mockRoleRepo := mock_repo.NewMockRolesRepository(ctrl)
				mockRoleRepo.EXPECT().FindAll(gomock.Any(), gomock.Any(), gomock.Any()).Return([]*model.Role{}, nil).AnyTimes()
				return fields{
					roleRepo: mockRoleRepo,
				}
			}(),
			wantErr: false,
		},
		{
			name: "failed find all roles",
			args: args{
				req: model.RequestCustomerOrganizationSearch{IsEasm: true},
			},
			fields: func() fields {
				mockRoleRepo := mock_repo.NewMockRolesRepository(ctrl)
				mockRoleRepo.EXPECT().FindAll(gomock.Any(), gomock.Any(), gomock.Any()).Return([]*model.Role{}, errors.New("foo")).AnyTimes()
				return fields{
					roleRepo: mockRoleRepo,
				}
			}(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAccount := mock_repo.NewMockAccountRepository(ctrl)
			mockAccount.EXPECT().Roles().Return(tt.fields.roleRepo).AnyTimes()
			mockMongo := mock_repo.NewMockGlobalRepository(ctrl)
			mockMongo.EXPECT().Account().Return(mockAccount).AnyTimes()
			inst := ManagerUserHandler{
				mongo: mockMongo,
			}
			if err := inst.searchEasmOrganization(context.Background(), tt.args.req, &bson.M{}); (err != nil) != tt.wantErr {
				t.Errorf("CustomerHandler.searchEasmOrganization() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCustomerHandler_GetUsers(t *testing.T) {
	logger, _ := pencil.New("test", pencil.InfoLevel, false, os.Stdout)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type fields struct {
	}
	tests := []struct {
		name     string
		fields   *fields
		query    any
		user     model.PPUserInfo
		wantCode int
	}{
		// {
		// 	name: "happy case",
		// 	fields: func() *fields {

		// 		return &fields{}
		// 	}(),
		// 	query: &model.SearchUser{
		// 		SearchUserStatistic: model.SearchUserStatistic{},
		// 		GroupRole:           []string{},
		// 		Offset:              0,
		// 		Size:                0,
		// 	},
		// 	user: &model.PPUserInfo{
		// 		OrgId:        "",
		// 		OrgName:      "",
		// 		UserId:       "",
		// 		UserFullname: "",
		// 	},
		// 	wantErr: false,
		// },
		{
			name: "bad request",
			fields: func() *fields {
				return &fields{}
			}(),
			query: map[string]any{
				"size": "a",
			},
			wantCode: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := ManagerUserHandler{
				logger: logger,
			}
			e := echo.New()
			bts, err := json.Marshal(tt.query)
			if err != nil {
				panic(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bts))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set(defs.PP_USER_INFO_CTX, tt.user)

			if err := h.GetUsers(c); err == nil {
				assert.Equal(t, tt.wantCode, rec.Code)
			}
		})
	}
}
