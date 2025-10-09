package mongo

import (
	"context"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type (
	repository interface {
		Name() (string, string)
	}

	GlobalRepository interface {
		Account() AccountRepository
		Settings() SettingsRepository
	}

	AccountRepository interface {
		GroupUser() GroupUserRepository
		Roles() RolesRepository
		User() UserRepository
		UserV3() UserV3Repository
		UserHistory() UserHistoryRepository
		Permissions() PermissionsRepository
		Features() FeaturesRepository
		UserSetting() UserSettingRepository
		OrgHistory() OrganizationHistoryRepo
		GroupUserV2() GroupUserRepositoryV2
		DefaultSetting() DefaultSettingRepository
		GroupSetting() GroupSettingRepository
	}

	SettingsRepository interface {
		Schedule() ScheduleRepository
	}

	PermissionsRepository interface {
		repository
		GetAll(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.Permissions, error)
		CountPermissions(ctx context.Context, query *bson.M) (int64, error)
		UpdateByID(ctx context.Context, id string, doc *model.UpdatePermission) error
		UpdateFeature(ctx context.Context, request model.UpdateFeature) error
		GetByPermissionID(ctx context.Context, permissions []string, offset, size int64) ([]*model.Permissions, error)
		Aggregate(ctx context.Context, pipeline []*bson.M, result any) error
	}
	FeaturesRepository interface {
		repository
		Find(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.Feature, error)
		Store(ctx context.Context, doc *model.Feature) error
		FindMany(ctx context.Context, query *bson.M) ([]*model.Feature, error)
		Aggregate(ctx context.Context, pipeline []*bson.M, result any) error
		GetByName(ctx context.Context, name string) (*model.Feature, error)
		UpdateByID(ctx context.Context, id string, document *model.Feature) error
		UpdateMany(ctx context.Context, query *bson.M, update bson.A, upsert bool) error
		GetByCode(ctx context.Context, code []string, offset, size int64) ([]*model.Feature, error)
		FindDescendantsByCode(ctx context.Context, code string, offset, size int64) ([]*model.Feature, error)
		Count(ctx context.Context, query *bson.M) (int64, error)
	}

	RolesRepository interface {
		repository
		HasPermission(role *model.Role, permission string) bool
		GetByName(ctx context.Context, name string) (*model.Role, error)
		Find(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.Role, error)
		FindAll(ctx context.Context, query *bson.M, sorts []string) ([]*model.Role, error)
		Store(ctx context.Context, document *model.Role) error
		UpdateByID(ctx context.Context, id string, document *model.Role) error
		DeleteByID(ctx context.Context, id string) error
		Count(ctx context.Context, query *bson.M) (int64, error)
		AggregationCount(ctx context.Context, query *bson.M, fields []string) (map[string][]mongo.ResultAggregationCount, error)
	}

	GroupUserRepository interface {
		repository
		Get(ctx context.Context, name string) (*model.GroupUser, error)
		GetByID(ctx context.Context, id string) (*model.GroupUser, error)
		Find(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.GroupUser, error)
		FindAll(ctx context.Context, query *bson.M, sorts []string) ([]*model.GroupUser, error)
		Count(ctx context.Context, query *bson.M) (int64, error)
		RunAggPipeline(ctx context.Context, pipeline []*bson.M, result any) error
		InsertOrg(ctx context.Context, org *model.Organization) error
		GetOrg(ctx context.Context, id string, isActive *bool) (*model.Organization, error)
		GetByRole(ctx context.Context, role string) (*model.GroupUser, error)
		UpdateOrg(ctx context.Context, org *model.Organization) error
		UpdateMany(ctx context.Context, query *bson.M, update bson.A, upsert bool) error
		FindAllOrgs(ctx context.Context, query *bson.M, sorts []string) ([]*model.Organization, error)
	}

	GroupUserRepositoryV2 interface {
		repository
		BulkUpdateById(ctx context.Context, orgs []*model.Organization) error
	}

	OrganizationHistoryRepo interface {
		repository
		Insert(ctx context.Context, org *model.OrganizationHistory) error
		InsertMany(ctx context.Context, orgs []*model.OrganizationHistory) error
		Find(ctx context.Context, query *bson.M, sorts []string) ([]*model.OrganizationHistory, error)
		Get(ctx context.Context, id string) (*model.OrganizationHistory, error)
	}

	UserRepository interface {
		repository
		Get(ctx context.Context, name string) (*model.User, error)
		GetByID(ctx context.Context, id string) (*model.User, error)
		UpdateByID(ctx context.Context, id string, userUpdate *model.UpdatePublicUserDTO) error
		DeleteByID(ctx context.Context, id string) error
		Find(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.User, error)
		FindUsersV2(ctx context.Context, query *bson.M, sorts []string, offset, size int64) ([]*model.PublicUser, error)
		CountUsersV2(ctx context.Context, query *bson.M) (int64, error)
		GetFieldStats(ctx context.Context, query *bson.M) (*model.SearchStatisticResponseAggs, error)
	}

	UserV3Repository interface {
		repository
		FindUserV3(ctx context.Context, pipeline []*bson.M) ([]*model.UserV3Aggregate, int64, error)
		StatisticV3(ctx context.Context, pipeline []*bson.M) (*model.SearchUserV3Statistic, error)
		Detail(ctx context.Context, pipeline []*bson.M) (*model.UserV3Aggregate, error)
		FindByUserName(ctx context.Context, username string) (*model.UserV3, error)
		Create(ctx context.Context, user *model.UserV3) error
		DeleteByID(ctx context.Context, id primitive.ObjectID) error
		FindByID(ctx context.Context, id primitive.ObjectID) (*model.UserV3, error)
		Update(ctx context.Context, id primitive.ObjectID, data bson.M) error
		CountByGroupID(ctx context.Context, groupID string) (int64, error)
	}

	UserHistoryRepository interface {
		repository
		Create(ctx context.Context, userHistory *model.UserHistory) error
		FindAll(ctx context.Context, pipeline []*bson.M) ([]*model.UserHistory, int64, error)
	}

	ScheduleRepository interface {
		repository
		GetSchedules(ctx context.Context, groupID string) ([]model.Schedule, error)
	}

	UserSettingRepository interface {
		repository
		GetUserSettings(ctx context.Context, username string) ([]model.UserSetting, error)
	}

	DefaultSettingRepository interface {
		repository
		GetDefaultSetting(ctx context.Context) (*model.DefaultConfig, error)
	}

	GroupSettingRepository interface {
		repository
		GetGroupSetting(ctx context.Context, groupId string) ([]model.GroupSetting, error)
	}
)
