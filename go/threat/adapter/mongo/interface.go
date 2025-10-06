package mongo

import (
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"

	"go.mongodb.org/mongo-driver/bson"
)

type (
	repository interface {
		Name() (string, string)
	}

	GlobalRepository interface {
		Account() AccountRepository
		Enduser() EnduserRepository
		ThreatReport() ThreatReportRepository
	}

	AccountRepository interface {
		GroupUser() AccountGroupUserRepository
		Configuration() AccountConfigurationRepository
		Support() AccountSupportRepository
		Roles() AccountRolesRepository
	}

	AccountGroupUserRepository interface {
		repository
		FindOne(query *bson.M, sorts []string, offset int64) (*model.GroupUser, error)
		FindByID(id string) (*model.GroupUser, error)
		FindByTenantID(id string) (*model.GroupUser, error)
		FindAll(query *bson.M, sorts []string) ([]*model.GroupUser, error)
	}

	AccountRolesRepository interface {
		repository
		FindAll(query *bson.M, sorts []string) ([]*model.Role, error)
	}

	AccountConfigurationRepository interface {
		repository
		FindOne(query *bson.M, sorts []string, offset int64) (*model.TTIConfig, error)
		GetConfig() (*model.TTIConfig, error)
	}

	AccountSupportRepository interface {
		repository
		Find(query *bson.M, sorts []string, size, offset int64) ([]*model.TTISupport, error)
		FindAll(query *bson.M, sorts []string) ([]*model.TTISupport, error)
	}

	/*
		Brand-Abuse Repository
	*/
	EnduserRepository interface {
		BrandAbuse() BrandAbuseRepository
	}

	BrandAbuseRepository interface {
		Alert() BrandAbuseAlertRepository
	}

	BrandAbuseAlertRepository interface {
		repository
		Find(query *bson.M, sorts []string, size, offset int64) ([]*model.BrandAbuseAlert, error)
		FindAll(query *bson.M, sorts []string) ([]*model.BrandAbuseAlert, error)
	}

	ThreatReportRepository interface {
		repository
		Find(query *bson.M, sorts []string, size, offset int64) ([]*model.ThreatReportAlert, error)
	}
)
