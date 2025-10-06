package defs

const (
	// Common
	DefaultChecker             = "Unknown"
	VersionCvssNA              = "N/A"
	VersionCvssV2              = "2.*"
	VersionCvssV3              = "3.*"
	VersionCvssV4              = "4.*"
	VersionCvssCNA             = "cna"
	VersionCvssV20             = "2.0"
	VersionCvssV30             = "3.0"
	VersionCvssV31             = "3.1"
	VersionCvssV40             = "4.0"
	VersionVcs10               = "1.0"
	SourceCvssNvd              = "NVD"
	SourceCvssCna              = "CNA"
	SourceCve                  = "Others"
	SourceCveCraw              = "NVD"
	PointNil                   = -1
	StatusCodeUnknown          = 0
	StatusCodeNew              = 1
	StatusCodeApproved         = 2
	StatusCodeWaitApprove      = 3
	StatusCodeDelivery         = 4
	StatusCodeReject           = 5
	TitleStatusCodeUnknown     = "Unknown"
	TitleStatusCodeNew         = "New"
	TitleStatusCodeApproved    = "Approved"
	TitleStatusCodeWaitApprove = "Wait Approve"
	TitleStatusCodeDelivery    = "Delivery"
	TitleStatusCodeReject      = "Reject"
	// Severity
	SeverityCodeUnknown   = 0
	SeverityCodeLow       = 1
	SeverityCodeMedium    = 2
	SeverityCodeHigh      = 3
	SeverityCodeCritical  = 4
	TitleSeverityUnknown  = "N/A"
	TitleSeverityLow      = "Low"
	TitleSeverityMedium   = "Medium"
	TitleSeverityHigh     = "High"
	TitleSeverityCritical = "Critical"
	// Vendor
	TitleVendorUnknown = "Unknown"
	// Regex
	RegexCVE             = `CVE-\d{4}-\d{4,7}`
	RegexCVSSVersion     = `^[234](\.\d)?$`
	RegexCWEID           = `^CWE-\d+$`
	RegexAffectedVersion = `^\d+(\.\d+){0,2}$`
	WorkerDefault        = 10
	PermissionAutoAlert  = "auto_alert"
	PermissionViewVul    = "view_vul"
	// History Type
	HistoryTypeSystem = "system"
	RegexReportLink   = `VTI_\d{4}_\d{4}`
	// Internal Flag
	MarkInternalFlag   = 1
	DeleteInternalFlag = 2
)

var (
	EnumVersionCvssV2 = []string{VersionCvssV20}
	EnumVersionCvssV3 = []string{VersionCvssV30, VersionCvssV31}
	// Mapping Severity
	MappingCveSeverity = map[int]string{
		SeverityCodeUnknown:  TitleSeverityUnknown,
		SeverityCodeLow:      TitleSeverityLow,
		SeverityCodeMedium:   TitleSeverityMedium,
		SeverityCodeHigh:     TitleSeverityHigh,
		SeverityCodeCritical: TitleSeverityCritical,
	}
	MappingCveSeverityRange = map[int]string{
		SeverityCodeUnknown:  "0-3",
		SeverityCodeLow:      "4-7",
		SeverityCodeMedium:   "8-10",
		SeverityCodeHigh:     "11-12",
		SeverityCodeCritical: "13-",
	}
	// Mapping Status
	MappingCveStatus = map[int]string{
		StatusCodeUnknown:     TitleStatusCodeUnknown,
		StatusCodeNew:         TitleStatusCodeNew,
		StatusCodeApproved:    TitleStatusCodeApproved,
		StatusCodeWaitApprove: TitleStatusCodeWaitApprove,
		StatusCodeDelivery:    TitleStatusCodeDelivery,
		StatusCodeReject:      TitleStatusCodeReject,
	}
	// CVSS
	EnumGlobalVersion = []string{
		VersionCvssNA, VersionCvssV2, VersionCvssV3, VersionCvssV4, VersionCvssCNA,
	}
	EnumVTIVersion = []string{
		VersionVcs10,
	}

	MappingCvss = map[string]interface{}{
		"unknown": map[string]interface{}{},
		"v2":      MappingCvssV2,
		"v3":      MappingCvssV3,
		"v4":      MappingCvssV4,
	}

	MappingCvssV2 = map[string]interface{}{
		"value":    VersionCvssV2,
		"versions": []string{VersionCvssV20},
		"severity": map[string]interface{}{
			"low": map[string]interface{}{
				"value": 1,
				"title": "Low",
				"range": "0.0-3.9",
			},
			"medium": map[string]interface{}{
				"value": 2,
				"title": "Medium",
				"range": "4.0-6.9",
			},
			"high": map[string]interface{}{
				"value": 3,
				"title": "High",
				"range": "7.0-10.0",
			},
		},
	}

	RangeCvssV2SeverityScore = map[int]interface{}{
		1: map[string]float32{"gte": 0.0, "lte": 3.9},
		2: map[string]float32{"gte": 4.0, "lte": 6.9},
		3: map[string]float32{"gte": 7.0, "lte": 10.0},
	}

	MappingCvssV3 = map[string]interface{}{
		"value":    VersionCvssV3,
		"versions": []string{VersionCvssV30, VersionCvssV31},
		"severity": map[string]interface{}{
			"unknown": map[string]interface{}{
				"value": 0,
				"title": "None",
				"range": "0.0",
			},
			"low": map[string]interface{}{
				"value": 1,
				"title": "Low",
				"range": "0.1-3.9",
			},
			"medium": map[string]interface{}{
				"value": 2,
				"title": "Medium",
				"range": "4.0-6.9",
			},
			"high": map[string]interface{}{
				"value": 3,
				"title": "High",
				"range": "7.0-8.9",
			},
			"critical": map[string]interface{}{
				"value": 4,
				"title": "Critical",
				"range": "9.0-10.0",
			},
		},
	}

	RangeCvssV3SeverityScore = map[int]interface{}{
		0: map[string]float32{"gte": 0.0, "lte": 0.0},
		1: map[string]float32{"gte": 0.1, "lte": 3.9},
		2: map[string]float32{"gte": 4.0, "lte": 6.9},
		3: map[string]float32{"gte": 7.0, "lte": 8.9},
		4: map[string]float32{"gte": 9.0, "lte": 10.0},
	}

	MappingCvssV4 = map[string]interface{}{
		"value":    VersionCvssV4,
		"versions": []string{VersionCvssV40},
		"severity": map[string]interface{}{
			"unknown": map[string]interface{}{
				"value": 0,
				"title": "None",
				"range": "0.0",
			},
			"low": map[string]interface{}{
				"value": 1,
				"title": "Low",
				"range": "0.1-3.9",
			},
			"medium": map[string]interface{}{
				"value": 2,
				"title": "Medium",
				"range": "4.0-6.9",
			},
			"high": map[string]interface{}{
				"value": 3,
				"title": "High",
				"range": "7.0-8.9",
			},
			"critical": map[string]interface{}{
				"value": 4,
				"title": "Critical",
				"range": "9.0-10.0",
			},
		},
	}

	RangeCvssV4SeverityScore = map[int]interface{}{
		0: map[string]float32{"gte": 0.0, "lte": 0.0},
		1: map[string]float32{"gte": 0.1, "lte": 3.9},
		2: map[string]float32{"gte": 4.0, "lte": 6.9},
		3: map[string]float32{"gte": 7.0, "lte": 8.9},
		4: map[string]float32{"gte": 9.0, "lte": 10.0},
	}

	// Mapping Checklist
	MappingCveChecklistVI = []map[string]interface{}{
		{
			"affect": map[string]interface{}{
				"title": "Mức độ ảnh hưởng của nguy cơ lỗ hổng đối với khách hàng",
				"checklist": []map[string]interface{}{
					{
						"title": "Lỗ hổng xảy ra trên dòng sản phẩm nổi tiếng, phổ biến, khi tấn công có thể ảnh hưởng đến diện rộng (VD: tấn công RCE trên Apache Server, khai thác giao thức RDP trên Windows, thiết bị IoT ngoài công cộng...)\n" +
							"Các dòng sản phẩm có thể ảnh hưởng rộng:\n" +
							"- Giao thức kết nối mạng (SMB, Samba, LDAP, ...)\n" +
							"- Các hệ thống web service phổ biến như Apache, Nginx,...\n" +
							"- Các thiết bị mạng, router, firewall, VPN doanh nghiệp phổ biến (Cisco, SAP, ...)\n" +
							"- Các phần mềm phổ biến: Word, Outlook, Access, Winrar, Foxit, ...\n" +
							"- Các hệ thống core của CMS phổ biến như Wordpress, Joomla!, Sharepoint, ...\n" +
							"- Các hệ thống database: MSSQL, Mongo-DB, PostgreSQL, ...\n" +
							"- Hạ tầng trọng yếu về viễn thông (tổng đài VoIP,...)\n" +
							"- Các hạ tầng liên quan tới Ngân hàng, tài chính (Core banking, máy POS, ...)",
						"point": 3,
					},
					{
						"title": "Lỗ hổng xảy ra trên:\n" +
							"- Dòng sản phẩm mang tính đặc thù cao (VD: Docker Server, Harbor, IBM BigFix, IBM Qradar...)\n" +
							"- Dòng sản phẩm bó hẹp (VD: SamSung, Iphone, thiết bị IoT trong nhà…)\n" +
							"- Các lỗ hổng tấn công vào Kernel trên Linux, khai thác các thư viện phần mềm, ...\n" +
							"- Các lỗ hổng khai thác vào browser (chrome, firefox, ...)",
						"point": 2,
					},
					{
						"title": "Lỗ hổng này xảy ra trên những dòng sản phẩm lạ, cực ít thông tin, không phổ biến, số lượng người dùng không nhiều - mức độ ảnh hưởng gần như là không có) (VD: search google quá ít thông tin về nó).\n" +
							"Dòng sản phẩm bên thứ 3, không phổ biến (VD: một plugin Wordpress có tầm 500 người dùng...)",
						"point": 1,
					},
				},
			},
			"exploit": map[string]interface{}{
				"title": "Mã khai thác",
				"checklist": []map[string]interface{}{
					{
						"title": "PoC public rộng trên báo chí, có thể dễ dàng tìm được mã khai thác trên Github, DB-Exploit…",
						"point": 3,
					},
					{
						"title": "PoC hẹp, chưa công bố mã khai thác (VD: PoC video trên Youtube nhưng mã khai thác không có).",
						"point": 2,
					},
					{
						"title": "Chưa có PoC được công bố.",
						"point": 1,
					},
				},
			},
			"patch": map[string]interface{}{
				"title": "Bản vá / Điều kiện khắc phục lỗ hổng",
				"checklist": []map[string]interface{}{
					{
						"title": "Lỗ hổng 0-day, 1-day chưa có bản vá cụ thể cụ thể từ hãng.",
						"point": 2,
					},
					{
						"title": "Lỗ hổng đã có bản vá hoặc workaround từ phía hãng.",
						"point": 1,
					},
				},
			},
			"ability": map[string]interface{}{
				"title": "Khả năng áp dụng thực tế",
				"checklist": []map[string]interface{}{
					{
						"title": "Không yêu cầu xác thực, không yêu cầu quyền",
						"point": 2,
					},
					{
						"title": "Yêu cầu xác thực hoặc có quyền user",
						"point": 1,
					},
					{
						"title": "None",
						"point": 0,
					},
				},
			},
			"condition": map[string]interface{}{
				"title": "Điều kiện khai thác lỗ hổng / Kịch bản tấn công",
				"checklist": []map[string]interface{}{
					{
						"title": "Một trong các điều kiện:\n" +
							"Khai thác được RCE hoặc có thể tấn công thẳng từ Internet mà không cần điều kiện gì / khai thác thực thi mã tùy ý chỉ cần 1 click của người dùng\n" +
							"Khai thác RCE",
						"point": 3,
					},
					{
						"title": "Tấn công qua Local, mạng Local, điều kiện khai thác phức tạp (VD: để khai thác được sản phẩm cần phải tấn công DNS server, cần intercept trafffic mạng....)\n" +
							"Khai thác nâng quyền hệ thống (EoP), DoS, lộ thông tin cấu hình, …",
						"point": 2,
					},
					{
						"title": "Tấn công qua tiếp cận vật lý",
						"point": 1,
					},
				},
			},
		},
	}

	// Mapping Checklist
	MappingCveChecklistEN = []map[string]interface{}{
		{
			"affect": map[string]interface{}{
				"title": "Impact of the vulnerability on customers",
				"checklist": []map[string]interface{}{
					{
						"title": "The vulnerability occurs on a well-known and popular product line and a related attack can have large-scale impacts (eg: RCE attack on Apache Server, exploitation of RDP protocol on Windows, exploitation of public IoT devices, etc.)\n" +
							"Product lines with large-scale impacts:\n" +
							"- Network protocol (SMB, Samba, LDAP, etc.)\n" +
							"- Popular web servers such as Apache, Nginx, etc.\n" +
							"- Popular enterprise network equipment, routers, firewalls, VPNs (Cisco, SAP, etc.)\n" +
							"- Popular applications: Word, Outlook, Access, Winrar, Foxit, etc.\n" +
							"- Core systems of popular CMS such as Wordpress, Joomla!, Sharepoint, etc.\n" +
							"- Database systems: MSSQL, Mongo-DB, PostgreSQL, etc.\n" +
							"- Critical infrastructure for telecommunications (VoIP switchboard, etc.)\n" +
							"- Infrastructure related to finance and banking (Core banking infrastructure, POS machines, etc.)",
						"point": 3,
					},
					{
						"title": "The vulnerability occurs on:\n" +
							"- Product lines with high specificity (eg: Docker Server, Harbor, IBM BigFix, IBM Qradar, etc.)\n" +
							"- Narrow product lines (eg: Samsung, Iphone, home IoT devices, etc.)\n" +
							"- The Linux kernel vulnerabilities, vulnerabilities in software libraries, etc.\n" +
							"- Browser vulnerabilities (Chrome, Firefox, etc.)",
						"point": 2,
					},
					{
						"title": "The vulnerability occurs on strange, unpopular product lines with extremely little information and inconsiderable number of users - the impact is negligible) (Ex: a google search result with too little information).\n" +
							"Uncommon third-party product lines (eg: a Wordpress plugin with about 500 users, etc.)",
						"point": 1,
					},
				},
			},
			"exploit": map[string]interface{}{
				"title": "Exploit",
				"checklist": []map[string]interface{}{
					{
						"title": "The PoC is widely publicized in the press and the exploit can be easily found on Github, DB-Exploit, etc.",
						"point": 3,
					},
					{
						"title": "The PoC is limited while the exploit hasn’t been published yet (eg: there is a PoC video on Youtube but the exploit is not available).",
						"point": 2,
					},
					{
						"title": "No PoC has been announced yet.",
						"point": 1,
					},
				},
			},
			"patch": map[string]interface{}{
				"title": "Condition for patch/workaround",
				"checklist": []map[string]interface{}{
					{
						"title": "The 0-day, 1-day vulnerability hasn’t had a specific patch released by the company.",
						"point": 2,
					},
					{
						"title": "The vulnerability has had a patch or workaround released by the company.",
						"point": 1,
					},
				},
			},
			"ability": map[string]interface{}{
				"title": "Applicability",
				"checklist": []map[string]interface{}{
					{
						"title": "No authentication required, no permissions required",
						"point": 2,
					},
					{
						"title": "Authentication or user rights required",
						"point": 1,
					},
					{
						"title": "None",
						"point": 0,
					},
				},
			},
			"condition": map[string]interface{}{
				"title": "Conditions of exploitation/Attack scenario",
				"checklist": []map[string]interface{}{
					{
						"title": "One of the conditions:\n" +
							"The attacker is able to carry out RCE or direct attack from the Internet without any conditions/The attacker is able to execute arbitrary code with just 1 click of the user\n" +
							"RCE attack",
						"point": 3,
					},
					{
						"title": "The attacker is able to attack via local machine, local network; under complicated exploitation conditions (For example, to exploit the product, attacks on DNS server and interception of network traffic are required)\n" +
							"EoP attack, DoS attack, exposure of configuration information, etc.",
						"point": 2,
					},
					{
						"title": "Physical attack",
						"point": 1,
					},
				},
			},
		},
	}
)

type Severity int

const (
	NoneSeverity Severity = -1
)

const (
	UnkownSeverity Severity = iota
	LowSeverity
	MediumSeverity
	HighSeverity
	CriticalSeverity
)

const (
	RegexCVSSV20Vector = `^AV:(N|A|L)/AC:(H|M|L)/Au:(N|S|M)/C:(N|P|C)/I:(N|P|C)/A:(N|P|C)(/.*)?$`
	RegexCVSSV31Vector = `^CVSS:3\.1(/AV:[NALP])(/AC:[LH])(/PR:[NLH])(/UI:[NR])(/S:[UC])(/C:[NLH])(/I:[NLH])(/A:[NLH])$`
	RegexCVSSV30Vector = `^CVSS:3\.0(/AV:[NALP])(/AC:[LH])(/PR:[NLH])(/UI:[NR])(/S:[UC])(/C:[NLH])(/I:[NLH])(/A:[NLH])$`
	RegexCVSSV40Vector = `^CVSS:4\.0(?:/[A-Z]{1,4}:[A-Za-z0-9\-_]+)+$`
)

var CVSSVectorRegexMap = map[string]string{
	VersionCvssV20: RegexCVSSV20Vector,
	VersionCvssV30: RegexCVSSV30Vector,
	VersionCvssV31: RegexCVSSV31Vector,
	VersionCvssV40: RegexCVSSV40Vector,
}

type ReportStatus int

const (
	ReportStatusNew     ReportStatus = 1
	ReportStatusApprove ReportStatus = 2
	ReportStatusReject  ReportStatus = 4
)
