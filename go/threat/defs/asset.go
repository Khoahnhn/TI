package defs

const (
	AssetTypeDomain         = "domain"
	AssetTypeIPv4           = "ipv4"
	AssetTypeIPv6           = "ipv6"
	AssetTypeIPv4Network    = "ipv4-network"
	AssetTypeIPv6Network    = "ipv6-network"
	AssetTypeProduct        = "product"
	AssetTypeSampleMD5      = "md5"
	AssetTypeSampleSHA1     = "sha1"
	AssetTypeSampleSHA256   = "sha256"
	AssetTypeSampleSHA512   = "sha512"
	AssetTypeURL            = "url"
	AssetTypeEmail          = "email"
	AssetStatusCodeUnknown  = 0
	AssetStatusCodePending  = 1
	AssetStatusCodeApproved = 2
	AssetStatusCodeReject   = 3
	RegexDomain             = `^(\*\.)?(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$`
	RegexSampleMD5          = `^[A-Fa-f0-9]{32}$`
	RegexSampleSHA1         = `^[A-Fa-f0-9]{40}$`
	RegexSampleSHA256       = `^[A-Fa-f0-9]{64}$`
	RegexSampleSHA512       = `^[A-Fa-f0-9]{128}$`
	RegexURL                = `^(http|https):\/\/(\w+:{0,1}\w*)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%!\-\/]))?$`
	RegexEmail              = `^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$`
)

var (
	MappingIndicatorType = map[string]string{
		AssetTypeDomain:       TypeDomain,
		AssetTypeIPv4:         TypeIPAddress,
		AssetTypeIPv6:         TypeIPAddress,
		AssetTypeSampleMD5:    TypeSample,
		AssetTypeSampleSHA1:   TypeSample,
		AssetTypeSampleSHA256: TypeSample,
		AssetTypeSampleSHA512: TypeSample,
		AssetTypeURL:          TypeURL,
		AssetTypeEmail:        TypeEmail,
	}
)
