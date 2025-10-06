package defs

const (
	// Environment
	EnvConfigFilePath = "CONFIG_FILE_PATH"
	EnvApiRoot        = "API_ROOT"
	// Default
	DefaultApiRoot          = "/customer/test"
	DefaultConfigFilePath   = "./config.yaml"
	DefaultTLDCacheFilePath = "./tld.cache"
	DefaultPoolSize         = 100
	// Handler
	HandlerMain                 = "API"
	HandlerCustomer             = "API-CUSTOMER"
	HandlerPermission           = "API-PERMISSION"
	HandlerFeature              = "API-MODULE"
	HandlerAsset                = "API-ASSET"
	HandlerAssetProduct         = "API-ASSET(PRODUCT)"
	HandlerAssetDomainIPAddress = "API-ASSET(DOMAIN-IPADDRESS)"
	HandlerOrganization         = "API-ORGANIZATION"
	HandlerManagerUser          = "API-MANAGER_USER"
	// Sort
	DefaultSort    = "-modified"
	DefaultCreator = "vti"

	RegexDomain = `^(\*\.)?(xn--)?([a-z0-9][a-z0-9-_]{0,61}\.)*?[a-z0-9][a-z0-9-_]{0,61}\.[a-z]{2,}$`
)
