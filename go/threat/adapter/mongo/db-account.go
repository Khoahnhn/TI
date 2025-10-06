package mongo

import mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"

type accountRepository struct {
	configuration AccountConfigurationRepository
	groupUser     AccountGroupUserRepository
	support       AccountSupportRepository
	roles         AccountRolesRepository
}

func NewAccountRepository(conf mg.Config) AccountRepository {
	// Success
	return &accountRepository{
		configuration: NewAccountConfigurationRepository(conf),
		groupUser:     NewAccountGroupUserRepository(conf),
		support:       NewAccountSupportRepository(conf),
		roles:         NewRoleRepository(conf),
	}
}

func (inst *accountRepository) Configuration() AccountConfigurationRepository {
	// Success
	return inst.configuration
}

func (inst *accountRepository) GroupUser() AccountGroupUserRepository {
	// Success
	return inst.groupUser
}

func (inst *accountRepository) Support() AccountSupportRepository {
	// Success
	return inst.support
}

func (inst *accountRepository) Roles() AccountRolesRepository {
	// Success
	return inst.roles
}
