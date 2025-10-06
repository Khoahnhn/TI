package mongo

import (
	"context"
	"errors"
	"testing"

	mock_package "gitlab.viettelcyber.com/ti-micro/ws-customer/mock/package"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.uber.org/mock/gomock"
)

func Test_featuresRepository_Store(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")

	type args struct {
		ctx context.Context
		doc *model.Feature
	}
	tests := []struct {
		name    string
		inst    *featuresRepository
		args    args
		wantErr bool
	}{
		{
			name: "error_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().InsertOne(gomock.Any(), gomock.Any(), gomock.Any()).Return(err)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: true,
		},
		{
			name: "happy_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().InsertOne(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.inst.Store(tt.args.ctx, tt.args.doc); (err != nil) != tt.wantErr {
				t.Errorf("featuresRepository.Store() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_featuresRepository_FindMany(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")
	type args struct {
		ctx   context.Context
		query *bson.M
	}
	tests := []struct {
		name    string
		inst    *featuresRepository
		args    args
		wantErr bool
	}{
		{
			name: "error_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(0), err)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: true,
		},
		{
			name: "happy_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(0), err)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.inst.FindMany(tt.args.ctx, tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("featuresRepository.FindMany() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_featuresRepository_Find(t *testing.T) {
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
		inst    *featuresRepository
		args    args
		wantErr bool
	}{
		{
			name: "error_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(0), err)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: true,
		},
		{
			name: "happy_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(0), err)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.inst.Find(tt.args.ctx, tt.args.query, tt.args.sorts, tt.args.offset, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("featuresRepository.Find() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_featuresRepository_GetByName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")
	type args struct {
		ctx  context.Context
		name string
	}
	tests := []struct {
		name    string
		inst    *featuresRepository
		args    args
		wantErr bool
	}{
		{
			name: "error_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(0), err)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: true,
		},
		{
			name: "empty_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_, _ string, _ *bson.M, _ []string, _, _ int64, result any) {
						resultPtr := result.(*[]*model.Feature)
						*resultPtr = []*model.Feature{}
					}).
					Return(int64(0), err)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: true,
		},
		{
			name: "happy_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_, _ string, _ *bson.M, _ []string, _, _ int64, result any) {
						resultPtr := result.(*[]*model.Feature)
						*resultPtr = []*model.Feature{
							{},
						}
					}).
					Return(int64(0), nil)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.inst.GetByName(tt.args.ctx, tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("featuresRepository.GetByName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_featuresRepository_UpdateByID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")
	type args struct {
		ctx      context.Context
		id       string
		document *model.Feature
	}
	tests := []struct {
		name    string
		inst    *featuresRepository
		args    args
		wantErr bool
	}{
		{
			name: "error_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().UpdateByID(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(err)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: true,
		},
		{
			name: "happy_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().UpdateByID(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.inst.UpdateByID(tt.args.ctx, tt.args.id, &model.Feature{}); (err != nil) != tt.wantErr {
				t.Errorf("featuresRepository.UpdateByID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_featuresRepository_GetByCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")
	type args struct {
		ctx    context.Context
		name   string
		offset int64
		size   int64
	}
	tests := []struct {
		name    string
		inst    *featuresRepository
		args    args
		wantErr bool
	}{
		{
			name: "error_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(0), err)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: true,
		},
		{
			name: "empty_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_, _ string, _ *bson.M, _ []string, _, _ int64, result any) {
						resultPtr := result.(*[]*model.Feature)
						*resultPtr = []*model.Feature{}
					}).
					Return(int64(0), err)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: true,
		},
		{
			name: "happy_case",
			inst: func() *featuresRepository {
				mockCon := mock_package.NewMockDatabase(ctrl)
				mockCon.EXPECT().FindMany(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_, _ string, _ *bson.M, _ []string, _, _ int64, result any) {
						resultPtr := result.(*[]*model.Feature)
						*resultPtr = []*model.Feature{
							{},
						}
					}).
					Return(int64(0), nil)
				return &featuresRepository{
					con: mockCon,
				}
			}(),
			args:    args{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.inst.GetByCode(tt.args.ctx, []string{tt.args.name}, tt.args.offset, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("featuresRepository.GetByCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
