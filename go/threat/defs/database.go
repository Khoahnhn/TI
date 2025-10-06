package defs

import "gitlab.viettelcyber.com/awesome-threat/library/udm"

const (
	IndexTIIntelligence  = "ti-intel"
	IndexTIDelivery      = "ti-delivery"
	IndexTTIAlert        = "tti_%s_alert"
	IndexTTIEvent        = "tti_%s_event"
	IndexCve             = "ti-cve"
	IndexCveCustomer     = "ti-cve-customer"
	IndexCveLifeCycle    = "ti-cve-lifecycle"
	IndexCveLifeCycleV2  = "ti-cve-lifecycle-v2"
	IndexCveLang         = "ti-cve-lang-%s"
	IndexCveRaw          = "ti-cve-raw"
	IndexCveHistory      = "ti-cve-history"
	IndexCveEpssHistory  = "ti-cve-epss-history"
	IndexCveInternalFlag = "ti-cve-internal-flag"
	IndexCpe             = "ti-cpe"
	IndexCpePopular      = "ti-cpe-popular"
	IndexAsset           = "ti-asset"
	IndexIOC             = "ti-ioc-%s"
	IndexIOCHistory      = "ti-history-ioc"
	IndexIOCDomain       = "ti-ioc-domain"
	IndexIOCIPAddress    = "ti-ioc-ipaddress"
	IndexIOCURL          = "ti-ioc-url"
	IndexIOCSample       = "ti-ioc-sample"
	// MongoDB
	// Account
	DbTIAccount      = "ti_account"
	ColConfiguration = "configuration"
	ColGroupUser     = "group_user"
	ColRoles         = "roles"
	// Enduser
	DbBrandAbuse = "brand-abuse"
	ColSupport   = "support"
	ColAlert     = "alert"
	// Threat
	DbThreatReport = "threat_report"
	ColReport      = "report"
)

var (
	ElasticsearchQueryFilterMatchAll = map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"match_all": map[string]interface{}{},
				},
			},
		},
	}

	MappingIOCIndex = map[string]string{
		TypeDomain:    IndexIOCDomain,
		TypeIPAddress: IndexIOCIPAddress,
		TypeURL:       IndexIOCURL,
		TypeSample:    IndexIOCSample,
	}

	MappingIOCTypeUDM = map[string]udm.EntityType{
		TypeDomain:    udm.EntityTypeDomain,
		TypeIPAddress: udm.EntityTypeIPAddress,
	}
)
