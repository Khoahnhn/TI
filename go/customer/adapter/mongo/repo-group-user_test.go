package mongo

import (
	"context"
	"errors"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"reflect"
	"testing"

	mock_package "gitlab.viettelcyber.com/ti-micro/ws-customer/mock/package"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.uber.org/mock/gomock"
)

const database = defs.DatabaseTIAccount

func Test_groupUserRepository_GetByRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	err := errors.New("foo")
	type args struct {
		ctx  context.Context
		role string
	}
	tests := []struct {
		name    string
		inst    *groupUserRepository
		args    args
		want    *model.GroupUser
		wantErr bool
	}{
		{
			name: "find_err",
			inst: func() *groupUserRepository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().
					FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(int64(0), err).
					Times(1)
				return &groupUserRepository{con, database}
			}(),
			want:    nil,
			wantErr: true,
		},
		{
			name: "find_empty",
			inst: func() *groupUserRepository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().
					FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(int64(0), nil).
					Times(1)
				return &groupUserRepository{con, database}
			}(),
			want:    nil,
			wantErr: true,
		},
		{
			name: "happy_case",
			inst: func() *groupUserRepository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().
					FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(int64(1), nil).
					Do(func(database string, collection string, query *bson.M, sorts []string, offset int64, size int64, results interface{}) {
						resultPtr := results.(*[]*model.GroupUser)
						*resultPtr = []*model.GroupUser{{}}
					}).
					Times(1)
				return &groupUserRepository{con, database}
			}(),
			want:    &model.GroupUser{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.inst.GetByRole(tt.args.ctx, tt.args.role)
			if (err != nil) != tt.wantErr {
				t.Errorf("groupUserRepository.GetByRole() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("groupUserRepository.GetByRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_groupUserRepository_GetOrg(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	err := errors.New("foo")
	type args struct {
		ctx      context.Context
		id       string
		isActive *bool
	}
	tests := []struct {
		name    string
		inst    *groupUserRepository
		args    args
		want    *model.Organization
		wantErr bool
	}{
		{
			name: "error_case",
			inst: func() *groupUserRepository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().
					FindOne(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(err).
					Times(1)
				return &groupUserRepository{con, database}
			}(),
			want:    nil,
			wantErr: true,
		},
		{
			name: "happy_case",
			inst: func() *groupUserRepository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().
					FindOne(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				return &groupUserRepository{con, database}
			}(),
			want:    &model.Organization{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.inst.GetOrg(tt.args.ctx, tt.args.id, tt.args.isActive)
			if (err != nil) != tt.wantErr {
				t.Errorf("groupUserRepository.GetOrg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("groupUserRepository.GetOrg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_groupUserRepository_RunAggPipeline(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	type args struct {
		ctx      context.Context
		pipeline []*bson.M
		isActive *bool
	}
	tests := []struct {
		name string
		inst *groupUserRepository
		args args
	}{
		{
			name: "happy_case",
			inst: func() *groupUserRepository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().
					Aggregate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				return &groupUserRepository{con, database}
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.inst.RunAggPipeline(tt.args.ctx, tt.args.pipeline, tt.args.isActive)
		})
	}
}

func Test_groupUserRepository_InsertOrg(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	type args struct {
		ctx context.Context
		org *model.Organization
	}
	tests := []struct {
		name string
		inst *groupUserRepository
		args args
	}{
		{
			name: "happy_case",
			inst: func() *groupUserRepository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().
					InsertOne(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				return &groupUserRepository{con, database}
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.inst.InsertOrg(tt.args.ctx, tt.args.org)
		})
	}
}

func Test_groupUserRepository_UpdateOrg(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	type args struct {
		ctx context.Context
		org *model.Organization
	}
	tests := []struct {
		name string
		inst *groupUserRepository
		args args
	}{
		{
			name: "happy_case",
			inst: func() *groupUserRepository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().
					UpdateByID(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				return &groupUserRepository{con, database}
			}(),
			args: args{
				org: &model.Organization{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.inst.UpdateOrg(tt.args.ctx, tt.args.org)
		})
	}
}

func Test_groupUserRepository_FindAllOrgs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	err := errors.New("foo")
	type args struct {
		ctx   context.Context
		query *bson.M
		sorts []string
	}
	tests := []struct {
		name    string
		inst    *groupUserRepository
		args    args
		want    []*model.Organization
		wantErr bool
	}{
		{
			name: "find_err",
			inst: func() *groupUserRepository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().
					FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(int64(0), err).
					Times(1)
				return &groupUserRepository{con, database}
			}(),
			want:    nil,
			wantErr: true,
		},
		{
			name: "find_err",
			inst: func() *groupUserRepository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().
					FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(int64(0), nil).
					Times(1)
				return &groupUserRepository{con, database}
			}(),
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.inst.FindAllOrgs(tt.args.ctx, tt.args.query, tt.args.sorts)
			if (err != nil) != tt.wantErr {
				t.Errorf("groupUserRepository.FindAllOrgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("groupUserRepository.FindAllOrgs() = %v, want %v", got, tt.want)
			}
		})
	}
}
