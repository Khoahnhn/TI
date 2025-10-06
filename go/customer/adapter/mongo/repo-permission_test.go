package mongo

import (
	"context"
	"errors"
	"reflect"
	"testing"

	mock_package "gitlab.viettelcyber.com/ti-micro/ws-customer/mock/package"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.uber.org/mock/gomock"
)

func Test_permissionsRepository_GetAll(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	err := errors.New("foo")
	type args struct {
		ctx    context.Context
		query  *bson.M
		sorts  []string
		offset int64
		size   int64
	}
	tests := []struct {
		name    string
		inst    *permissionsRepository
		args    args
		want    []*model.Permissions
		wantErr bool
	}{
		{
			name: "find_err",
			inst: func() *permissionsRepository {
				con := mock_package.NewMockDatabase(ctrl)

				con.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(int64(0), err).Times(1)
				return &permissionsRepository{con}
			}(),
			want:    nil,
			wantErr: true,
		},
		{
			name: "happy_case",
			inst: func() *permissionsRepository {
				con := mock_package.NewMockDatabase(ctrl)

				con.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(int64(0), nil).Times(1)
				return &permissionsRepository{con}
			}(),
			want:    []*model.Permissions{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.inst.GetAll(tt.args.ctx, tt.args.query, tt.args.sorts, tt.args.offset, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("permissionsRepository.GetAll() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("permissionsRepository.GetAll() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_permissionsRepository_CountPermissions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	err := errors.New("foo")
	type args struct {
		ctx   context.Context
		query *bson.M
	}
	tests := []struct {
		name    string
		inst    *permissionsRepository
		args    args
		want    int64
		wantErr bool
	}{
		{
			name: "find_err",
			inst: func() *permissionsRepository {
				con := mock_package.NewMockDatabase(ctrl)

				con.EXPECT().Count(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(int64(0), err).Times(1)
				return &permissionsRepository{con}
			}(),
			want:    0,
			wantErr: true,
		},
		{
			name: "happy_case",
			inst: func() *permissionsRepository {
				con := mock_package.NewMockDatabase(ctrl)

				con.EXPECT().Count(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(int64(0), nil).Times(1)
				return &permissionsRepository{con}
			}(),
			want:    0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.inst.CountPermissions(tt.args.ctx, tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("permissionsRepository.CountPermissions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("permissionsRepository.CountPermissions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_permissionsRepository_UpdateByID(t *testing.T) {
	type args struct {
		ctx context.Context
		id  string
		doc *model.UpdatePermission
	}
	tests := []struct {
		name    string
		inst    *permissionsRepository
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.inst.UpdateByID(tt.args.ctx, tt.args.id, tt.args.doc); (err != nil) != tt.wantErr {
				t.Errorf("permissionsRepository.UpdateByID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
