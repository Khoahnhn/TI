package mongo

import (
	"context"
	"errors"
	"reflect"
	"testing"

	mock_package "gitlab.viettelcyber.com/ti-micro/ws-customer/mock/package"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/mock/gomock"
)

func Test_userV3Repository_CountByGroupID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	err := errors.New("foo")
	type args struct {
		ctx     context.Context
		groupID string
	}
	tests := []struct {
		name    string
		u       userV3Repository
		args    args
		want    int64
		wantErr bool
	}{
		{
			name: "error_case",
			u: func() userV3Repository {
				mockMongo := mock_package.NewMockDatabase(ctrl)
				mockMongo.EXPECT().Count(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(int64(0), err).Times(1)
				return userV3Repository{
					con: mockMongo,
				}
			}(),
			args: args{
				ctx:     context.TODO(),
				groupID: "123",
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "happy_case",
			u: func() userV3Repository {
				mockMongo := mock_package.NewMockDatabase(ctrl)
				mockMongo.EXPECT().Count(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(int64(5), nil).Times(1)
				return userV3Repository{
					con: mockMongo,
				}
			}(),
			args: args{
				ctx:     context.TODO(),
				groupID: "123",
			},
			want:    5,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.u.CountByGroupID(tt.args.ctx, tt.args.groupID)
			if (err != nil) != tt.wantErr {
				t.Errorf("userV3Repository.CountByGroupID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("userV3Repository.CountByGroupID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_userV3Repository_Update(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		ctx  context.Context
		id   primitive.ObjectID
		data bson.M
	}
	tests := []struct {
		name    string
		u       userV3Repository
		args    args
		wantErr bool
	}{
		{
			name: "happy_case",
			u: func() userV3Repository {
				mockMongo := mock_package.NewMockDatabase(ctrl)
				mockMongo.EXPECT().UpdateByID(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Times(1)
				return userV3Repository{
					con: mockMongo,
				}
			}(),
			args:    args{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.u.Update(tt.args.ctx, tt.args.id, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("userV3Repository.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_userV3Repository_FindByID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")
	type args struct {
		ctx context.Context
		id  primitive.ObjectID
	}
	tests := []struct {
		name    string
		u       userV3Repository
		args    args
		want    *model.UserV3
		wantErr bool
	}{
		{
			name: "error_case",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().FindOne(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(err)
				return userV3Repository{
					con: con,
				}
			}(),
			args:    args{},
			want:    nil,
			wantErr: true,
		},
		{
			name: "happy_case",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().FindOne(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
				return userV3Repository{
					con: con,
				}
			}(),
			args:    args{},
			want:    &model.UserV3{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.u.FindByID(tt.args.ctx, tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("userV3Repository.FindByID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("userV3Repository.FindByID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_userV3Repository_DeleteByID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")

	type args struct {
		ctx context.Context
		id  primitive.ObjectID
	}
	tests := []struct {
		name    string
		u       userV3Repository
		args    args
		wantErr bool
	}{
		{
			name: "error_case",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().DeleteByID(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(err).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			args:    args{},
			wantErr: true,
		},
		{
			name: "happy_case",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().DeleteByID(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			args:    args{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.u.DeleteByID(tt.args.ctx, tt.args.id); (err != nil) != tt.wantErr {
				t.Errorf("userV3Repository.DeleteByID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_userV3Repository_Create(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		ctx  context.Context
		user *model.UserV3
	}
	tests := []struct {
		name    string
		u       userV3Repository
		args    args
		wantErr bool
	}{
		{
			name: "empty_user",
			u:    userV3Repository{},
			args: args{
				user: nil,
			},
			wantErr: true,
		},
		{
			name: "happy_case",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().InsertOne(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			args: args{
				user: &model.UserV3{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.u.Create(tt.args.ctx, tt.args.user); (err != nil) != tt.wantErr {
				t.Errorf("userV3Repository.Create() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_userV3Repository_FindByUserName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")

	type args struct {
		ctx      context.Context
		username string
	}
	tests := []struct {
		name    string
		u       userV3Repository
		args    args
		want    *model.UserV3
		wantErr bool
	}{
		{
			name: "find_error",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().FindOne(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(err).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want:    nil,
			wantErr: true,
		},
		{
			name: "not_found",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().FindOne(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("not found")).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want:    nil,
			wantErr: false,
		},
		{
			name: "happy_case",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().FindOne(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want:    &model.UserV3{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.u.FindByUserName(tt.args.ctx, tt.args.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("userV3Repository.FindByUserName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("userV3Repository.FindByUserName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_userV3Repository_Detail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")

	type args struct {
		ctx      context.Context
		pipeline []*bson.M
	}
	tests := []struct {
		name    string
		u       userV3Repository
		args    args
		want    *model.UserV3Aggregate
		wantErr bool
	}{
		{
			name: "get_error",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().Aggregate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(err).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want:    nil,
			wantErr: true,
		},
		{
			name: "not_found",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().Aggregate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Do(
					func(_, _ string, _ []*bson.M, result any) {
						resultPtr := result.(*[]*model.UserV3Aggregate)
						*resultPtr = []*model.UserV3Aggregate{}
					}).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want:    nil,
			wantErr: false,
		},
		{
			name: "happy_case",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().Aggregate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Do(
					func(_, _ string, _ []*bson.M, result any) {
						resultPtr := result.(*[]*model.UserV3Aggregate)
						*resultPtr = []*model.UserV3Aggregate{
							{},
						}
					}).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want:    &model.UserV3Aggregate{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.u.Detail(tt.args.ctx, tt.args.pipeline)
			if (err != nil) != tt.wantErr {
				t.Errorf("userV3Repository.Detail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("userV3Repository.Detail() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_userV3Repository_StatisticV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")

	type args struct {
		ctx      context.Context
		pipeline []*bson.M
	}
	tests := []struct {
		name    string
		u       userV3Repository
		args    args
		want    *model.SearchUserV3Statistic
		wantErr bool
	}{
		{
			name: "agg_err",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().Aggregate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(err).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want:    nil,
			wantErr: true,
		},
		{
			name: "empty_res",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().Aggregate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Do(func(_, _ string, _ []*bson.M, result any) {
					resultPtr := result.(*[]model.FacetResult)
					*resultPtr = []model.FacetResult{}
				}).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want:    &model.SearchUserV3Statistic{},
			wantErr: false,
		},
		{
			name: "happy_case",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().Aggregate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Do(func(_, _ string, _ []*bson.M, result any) {
					resultPtr := result.(*[]model.FacetResult)
					*resultPtr = []model.FacetResult{
						{
							Country: []struct {
								Values []string `bson:"values"`
							}{
								{
									Values: []string{"Viet Nam"},
								},
							},
							Package: []struct {
								Values []string `bson:"values"`
							}{
								{
									Values: []string{"test"},
								},
							},
						},
					}
				}).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want: &model.SearchUserV3Statistic{
				Country: []string{"Viet Nam"},
				Package: []string{"test"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.u.StatisticV3(tt.args.ctx, tt.args.pipeline)
			if (err != nil) != tt.wantErr {
				t.Errorf("userV3Repository.StatisticV3() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("userV3Repository.StatisticV3() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_userV3Repository_FindUserV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")

	type args struct {
		ctx      context.Context
		pipeline []*bson.M
	}
	tests := []struct {
		name    string
		u       userV3Repository
		args    args
		want    []*model.UserV3Aggregate
		want1   int64
		wantErr bool
	}{
		{
			name: "agg_err",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().Aggregate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(err).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want:    nil,
			want1:   0,
			wantErr: true,
		},
		{
			name: "empty_res",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().Aggregate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want:    []*model.UserV3Aggregate{},
			want1:   0,
			wantErr: false,
		},
		{
			name: "happy_case",
			u: func() userV3Repository {
				con := mock_package.NewMockDatabase(ctrl)
				con.EXPECT().Aggregate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil).
					Do(func(_, _ any, _ []*bson.M, result any) {
						resultPtr := result.(*[]struct {
							Data  []*model.UserV3Aggregate `bson:"data"`
							Total []struct {
								Count int64 `bson:"count"`
							} `bson:"total"`
						})
						*resultPtr = []struct {
							Data  []*model.UserV3Aggregate `bson:"data"`
							Total []struct {
								Count int64 `bson:"count"`
							} `bson:"total"`
						}{
							{
								Data: nil,
								Total: []struct {
									Count int64 `bson:"count"`
								}{
									{
										Count: 2,
									},
								},
							},
						}
					}).Times(1)
				return userV3Repository{
					con: con,
				}
			}(),
			want:    nil,
			want1:   2,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := tt.u.FindUserV3(tt.args.ctx, tt.args.pipeline)
			if (err != nil) != tt.wantErr {
				t.Errorf("userV3Repository.FindUserV3() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("userV3Repository.FindUserV3() got = %#v, want %#v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("userV3Repository.FindUserV3() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
