package defs

const (
	DefaultConfigFilePath         = "./config-dev.yaml"
	DefaultAPIRoot                = "/lookup/test"
	DefaultTLDCacheFilePath       = "./tld.cache"
	DefaultMaxLimit               = 20
	DefaultMaxIdentifyLimit       = 200
	DefaultMaxLookupMultipleLimit = 200

	// Handler
	HandlerMain      = "MAIN"
	HandlerLookup    = "API-LOOKUP"
	HandlerDomain    = "API-DOMAIN"
	HandlerIPAddress = "API-IP"
	HandlerURL       = "API-URL"
	HandlerFile      = "API-FILE"
	HandlerCVE       = "API-CVE"

	// Timeout
	DefaultDbTimeout    = 120
	DefaultRestyTimeout = 60

	// Enrichment API Routes
	RouteDomainRankAlexa     = "domain/rank/alexa"
	RouteDomainRankCisco     = "domain/rank/cisco"
	RouteDomainWhois         = "domain/whois"
	RouteDomainSubdomain     = "domain/subdomain"
	RouteDomainSibling       = "domain/sibling"
	RouteDomainPassiveDNS    = "domain/passive-dns"
	RouteIPAddressArtifact   = "ipaddress/artifact"
	RouteIPAddressPassiveDNS = "ipaddress/passive-dns"
	RouteIPAddressSubnet     = "ipaddress/subnet-host"

	// Regex
	RegexDomain = `^(\*\.)?(xn--)?([a-z0-9][a-z0-9-_]{0,61}\.)*?[a-z0-9][a-z0-9-_]{0,61}\.[a-z]{2,}$`
	RegexURL    = `^(http|https):\/\/(\w+:{0,1}\w*)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%!\-\/]))?$`
	RegexCVE    = `CVE-\d{4}-\d{4,7}`

	// RiskScore
	RiskScoreUnknown = 10

	// DNS Crawl
	SourceVTIDatamining = "vti-datamining"
)

const (
	LookupTypeDomain  = "domain"
	LookupTypeIP      = "ip"
	LookupTypeHash    = "hash"
	LookupTypeCVE     = "cve"
	LookupTypeUnknown = "unknown"
)

var EnumLookupType = map[string]interface{}{
	LookupTypeDomain:  emptyStruct,
	LookupTypeIP:      emptyStruct,
	LookupTypeHash:    emptyStruct,
	LookupTypeCVE:     emptyStruct,
	LookupTypeUnknown: emptyStruct,
}
