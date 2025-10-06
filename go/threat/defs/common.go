package defs

const (
	DefaultApiRoot          = "/threat/test"
	DefaultConfigFilePath   = "./config.yaml"
	DefaultUser             = "Unknown"
	DefaultTLDCacheFilePath = "./tld.cache"
	// Handler
	HandlerMain      = "MAIN"
	HandlerCve       = "CVE-API"
	HandlerCpe       = "CPE-API"
	HandlerIndicator = "INDICATOR-API"
	// Feature export
	FeatureBrandAbuse                = "brand-abuse"
	FeatureIntelligenceVulnerability = "intelligence-vulnerability"
	FeatureIntelligenceMalware       = "intelligence-malware"
	// Severity
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	PointCritical    = 16
	PointHigh        = 11
	PointMedium      = 6
	PointLow         = 0
	PointTTICritical = 3
	PointTTIHigh     = 2
	PointTTIMedium   = 1
	PointTTILow      = 0

	TitleCritical                        = "NGHIÊM TRỌNG"
	TitleHigh                            = "CAO"
	TitleMedium                          = "TRUNG BÌNH"
	TitleLow                             = "THẤP"
	TitleCriticalEN                      = "CRITICAL"
	TitleHighEN                          = "HIGH"
	TitleMediumEN                        = "MEDIUM"
	TitleLowEN                           = "LOW"
	TitlePending                         = "Chưa xử lý"
	TitleInprogress                      = "Đang thực hiện"
	TitleDone                            = "Hoàn thành"
	TitleReject                          = "Loại bỏ"
	TitlePendingEN                       = "Pending"
	TitleInprogressEN                    = "In progress"
	TitleDoneEN                          = "Done"
	TitleRejectEN                        = "Reject"
	TitleTypeTakedown                    = "Takedown"
	TitleTypeOther                       = "Khác"
	TitleTypeTakedownEN                  = "Takedown"
	TitleTypeOtherEN                     = "Other"
	TitleCategoryPhishing                = "Lừa đảo"
	TitleCategoryImpersonate             = "Mạo danh"
	TitleCategoryImpersonateSocial       = "Mạo danh trên MXH"
	TitleCategoryMalware                 = "Mã độc"
	TitleCategoryVulnerability           = "Lỗ hổng"
	TitleCategoryLeak                    = "Lộ lọt"
	TitleCategoryCompromisedSystem       = "Hệ thống nhiễm mã độc"
	TitleCategoryPortAnomaly             = "Port mở bất thường"
	TitleCategoryTargetedVulnerability   = "Lỗ hổng dịch vụ"
	TitleCategoryPhishingEN              = "Phishing"
	TitleCategoryImpersonateEN           = "Impersonate"
	TitleCategoryImpersonateSocialEN     = "Impersonate Social"
	TitleCategoryMalwareEN               = "Malware"
	TitleCategoryVulnerabilityEN         = "Vulnerability"
	TitleCategoryLeakEN                  = "Leak"
	TitleCategoryCompromisedSystemEN     = "Compromised System"
	TitleCategoryPortAnomalyEN           = "Open Port Anomaly"
	TitleCategoryTargetedVulnerabilityEN = "Targeted Vulnerability"

	TitleNA = "N/A"

	PolicyPublish = "PUBLIC"
	PolicyPrivate = "PRIVATE"
	PolicyCustom  = "CUSTOM"

	ExportTTIAlert   = "alert"
	ExportTTISupport = "support"

	SLAPass    = "Đạt"
	SLAFail    = "Không Đạt"
	SLANa      = "N/A"
	StatusPass = "pass"
	StatusFail = "fail"
	StatusNa   = "n/a"

	StatusPending    = "pending"
	StatusInprogress = "inprogress"
	StatusDone       = "done"
	StatusReject     = "reject"
	// Type
	TypeTTISupportTakedown = "takedown"
	TypeTTISupportOther    = "other"
	// Category
	CategoryPhishing              = "phishing"
	CategoryImpersonate           = "impersonate"
	CategoryImpersonateSocial     = "impersonate_social"
	CategoryMalware               = "malware"
	CategoryVulnerability         = "vulnerability"
	CategoryLeak                  = "leak"
	CategoryCompromiseSystem      = "compromised_system"
	CategoryPortAnomaly           = "port_anomaly"
	CategoryTargetedVulnerability = "targeted_vulnerability"

	PortAnomaly      = "port_anomaly"
	ImpersonateBrand = "impersonate_brand"
	Malware          = "malware"

	// Export
	DefaultTTIAlertExport           = "./static/TTI-Report.xlsx"
	DefaultReportTemplate           = "./static/report-template.html"
	DefaultReportTemplateWithTarget = "./static/report-template-with-target.html"
	DefaultAlertFileName            = "Report_Alert_%s.xlsx"
	DefaultTTIFileName              = "Report_TTI_%s.xlsx"
	DefaultTempFilePath             = "./temp/%s"
	DefaultAlertExport              = "./static/Threat-Report.xlsx"
	SheetVulnerability              = "Vulnerability"
	SheetMalware                    = "Malware"
	SheetBrandAbuse                 = "Brand Abuse"
	SheetTTIAlert                   = "Alert"
	SheetTTISupport                 = "Request Support"
	TitleSummaryVulnerability       = "Viettel Threat Intelligence thống kê cảnh báo lỗ hổng %s"
	TitleSummaryMalware             = "Viettel Threat Intelligence thống kê cảnh báo mã độc %s"
	TitleSummaryBrandAbuse          = "Viettel Threat Intelligence thống kê cảnh báo lạm dụng thương hiệu %s"
	//TitleSummaryTTIAlert            = "Viettel Threat Intelligence thống kê cảnh báo %s"
	//TitleSummaryTTISupport          = "Viettel Threat Intelligence thống kê trạng thái yêu cầu hỗ trợ %s"
	TitleAlertExport      = "Thống kê cảnh báo %s"
	TitleAlertExportDebug = "[Test] Thống kê cảnh báo %s"

	SuffixDateGte = "từ %s đến nay"
	SuffixDateLte = "đến %s"
	SuffixDate    = "từ %s đến %s"

	DefaultTimeout       = 3
	DefaultMaxSizeExport = 10000
	// Language
	LangVI = "vi"
	LangEN = "en"
)

var (
	EnumLanguage = []string{LangVI, LangEN}

	EnumFeature  = []string{FeatureBrandAbuse, FeatureIntelligenceVulnerability, FeatureIntelligenceMalware}
	EnumSeverity = []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	EnumStatus   = []string{StatusPass, StatusFail, StatusNa}

	MappingSeverity = map[string]int{
		SeverityCritical: PointCritical,
		SeverityHigh:     PointHigh,
		SeverityMedium:   PointMedium,
		SeverityLow:      PointLow,
	}

	MappingPointTitle = map[int]string{
		PointCritical: TitleCritical,
		PointHigh:     TitleHigh,
		PointMedium:   TitleMedium,
		PointLow:      TitleLow,
	}

	MappingTTIPointTitle = map[string]map[int]string{
		LangVI: {
			PointTTICritical: TitleCritical,
			PointTTIHigh:     TitleHigh,
			PointTTIMedium:   TitleMedium,
			PointTTILow:      TitleLow,
		},
		LangEN: {
			PointTTICritical: TitleCriticalEN,
			PointTTIHigh:     TitleHighEN,
			PointTTIMedium:   TitleMediumEN,
			PointTTILow:      TitleLowEN,
		},
	}

	MappingTTIAlertCategoryTitle = map[string]map[string]string{
		LangVI: {
			CategoryPhishing:              TitleCategoryPhishing,
			CategoryImpersonate:           TitleCategoryImpersonate,
			CategoryImpersonateSocial:     TitleCategoryImpersonateSocial,
			CategoryMalware:               TitleCategoryMalware,
			CategoryVulnerability:         TitleCategoryVulnerability,
			CategoryLeak:                  TitleCategoryLeak,
			CategoryCompromiseSystem:      TitleCategoryCompromisedSystem,
			CategoryPortAnomaly:           TitleCategoryPortAnomaly,
			CategoryTargetedVulnerability: TitleCategoryTargetedVulnerability,
		},
		LangEN: {
			CategoryPhishing:              TitleCategoryPhishingEN,
			CategoryImpersonate:           TitleCategoryImpersonateEN,
			CategoryImpersonateSocial:     TitleCategoryImpersonateSocialEN,
			CategoryMalware:               TitleCategoryMalwareEN,
			CategoryVulnerability:         TitleCategoryVulnerabilityEN,
			CategoryLeak:                  TitleCategoryLeakEN,
			CategoryCompromiseSystem:      TitleCategoryCompromisedSystemEN,
			CategoryPortAnomaly:           TitleCategoryPortAnomalyEN,
			CategoryTargetedVulnerability: TitleCategoryTargetedVulnerabilityEN,
		},
	}

	MappingTTISupportStatusTitle = map[string]map[string]string{
		LangVI: {
			StatusPending:    TitlePending,
			StatusInprogress: TitleInprogress,
			StatusDone:       TitleDone,
			StatusReject:     TitleReject,
		},
		LangEN: {
			StatusPending:    TitlePendingEN,
			StatusInprogress: TitleInprogressEN,
			StatusDone:       TitleDoneEN,
			StatusReject:     TitleRejectEN,
		},
	}

	EnumTTIExport = []string{
		ExportTTIAlert,
		ExportTTISupport,
	}

	MappingTTISupportTypeTitle = map[string]map[string]string{
		LangVI: {
			TypeTTISupportTakedown: TitleTypeTakedown,
			TypeTTISupportOther:    TitleTypeOther,
		},
		LangEN: {
			TypeTTISupportTakedown: TitleTypeTakedownEN,
			TypeTTISupportOther:    TitleTypeOtherEN,
		},
	}

	MappingFeatureType = map[string]string{
		FeatureIntelligenceMalware:       "malware",
		FeatureIntelligenceVulnerability: "vulner",
	}

	MappingSeveritySLA = map[int]float64{
		PointCritical: 24.0,
		PointHigh:     24.0,
		PointMedium:   72.0,
		PointLow:      72.0,
	}

	MappingSLAStatus = map[string]string{
		SLAPass: StatusPass,
		SLAFail: StatusFail,
		SLANa:   StatusNa,
	}

	MappingPolicy = map[int]string{
		0: PolicyPublish,
		1: PolicyPrivate,
		2: PolicyCustom,
	}

	MappingLanguage = map[string]string{
		LangEN: "EN",
		LangVI: "VI",
	}

	MappingLanguageStatistic = map[string]string{
		LangEN:  "EN",
		LangVI:  "VI",
		"vi,en": "VI,EN",
	}
)

type TLP int

const (
	TLPUnknown TLP = iota
	TLPWhite
	TLPGreen
	TLPAmber
	TLPRed
)
