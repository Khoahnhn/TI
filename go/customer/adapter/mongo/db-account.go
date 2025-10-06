package mongo

import "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"

type accountRepository struct {
	groupUser      GroupUserRepository
	roles          RolesRepository
	user           UserRepository
	userV3         UserV3Repository
	permissions    PermissionsRepository
	features       FeaturesRepository
	userHistory    UserHistoryRepository
	userSetting    UserSettingRepository
	orgHistory     OrganizationHistoryRepo
	groupUserV2    GroupUserRepositoryV2
	defaultSetting DefaultSettingRepository
	groupSetting   GroupSettingRepository
}

func (inst *accountRepository) UserSetting() UserSettingRepository {
	//TODO implement me
	return inst.userSetting
}

func NewAccountRepository(conf mongo.Config, database string) AccountRepository {
	// Success
	return &accountRepository{
		groupUser:      NewGroupUserRepository(conf, database),
		roles:          NewRoleRepository(conf, database),
		user:           NewUserRepository(conf, database),
		userV3:         NewUserV3Repository(conf, database),
		permissions:    NewPermissionsRepository(conf),
		features:       NewFeaturesRepository(conf),
		userHistory:    NewUserHistoryRepository(conf, database),
		userSetting:    NewUserSettingRepository(conf, database),
		orgHistory:     NewOrgHistoryRepo(conf),
		groupUserV2:    NewGroupUserRepositoryV2(conf),
		defaultSetting: NewDefaultSettingRepository(conf),
		groupSetting:   NewGroupSettingRepository(conf),
	}
}

func (inst *accountRepository) GroupUser() GroupUserRepository {
	// Success
	return inst.groupUser
}

func (inst *accountRepository) Roles() RolesRepository {
	// Success
	return inst.roles
}

func (inst *accountRepository) User() UserRepository {
	// Success
	return inst.user
}

func (inst *accountRepository) UserV3() UserV3Repository {
	//TODO implement me
	return inst.userV3
}

func (inst *accountRepository) Permissions() PermissionsRepository {
	// Success
	return inst.permissions
}

func (inst *accountRepository) Features() FeaturesRepository {
	// Success
	return inst.features
}

func (inst *accountRepository) UserHistory() UserHistoryRepository {
	//TODO implement me
	return inst.userHistory
}

func (inst *accountRepository) OrgHistory() OrganizationHistoryRepo {
	return inst.orgHistory
}

func (inst *accountRepository) GroupUserV2() GroupUserRepositoryV2 {
	return inst.groupUserV2
}

func (inst *accountRepository) DefaultSetting() DefaultSettingRepository {
	return inst.defaultSetting
}

func (inst *accountRepository) GroupSetting() GroupSettingRepository {
	return inst.groupSetting
}
