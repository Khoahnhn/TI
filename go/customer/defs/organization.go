package defs

type OrgHistoryEvent string

const (
	OrgEventCreate     OrgHistoryEvent = "create"
	OrgEventEdit       OrgHistoryEvent = "edit"
	OrgEventActive     OrgHistoryEvent = "active"
	OrgEventInActive   OrgHistoryEvent = "inactive"
	OrgEventBuyPackage OrgHistoryEvent = "buy_package"
)

var IndustryKeyMap = map[string]string{
	"agriculture":                "Nông nghiệp",
	"aerospace":                  "Hàng không vũ trụ",
	"automotive":                 "Ô tô",
	"communications":             "Truyền thông",
	"construction":               "Xây dựng",
	"defence":                    "Quốc phòng",
	"education":                  "Giáo dục",
	"energy":                     "Năng lượng",
	"entertainment":              "Giải trí",
	"financial-services":         "Tài chính-dịch vụ",
	"government-national":        "Chính phủ-quốc gia",
	"government-regional":        "Chính phủ-khu vực",
	"government-local":           "Chính phủ-địa phương",
	"government-public-services": "Chính phủ-dịch vụ công",
	"healthcare":                 "Chăm sóc sức khỏe",
	"hospitality-leisure":        "Khách sạn-giải trí",
	"infrastructure":             "Cơ sở hạ tầng",
	"insurance":                  "Bảo hiểm",
	"manufacturing":              "Sản xuất",
	"mining":                     "Khai thác",
	"non-profit":                 "Phi lợi nhuận",
	"pharmaceuticals":            "Dược phẩm",
	"retail":                     "Bán lẻ",
	"technology":                 "Công nghệ",
	"telecommunications":         "Viễn thông",
	"transportation":             "Giao thông vận tải",
	"utilities":                  "Tiện ích",
	"banking":                    "Ngân hàng",
	"other":                      "Lĩnh vực khác",
}

var OrganizationCompKeys = []string{
	"name",
	"description",
	"active",
	"parent",
	"industry",
	"role",
	"effective_time",
	"expired_time",
	"company_size",
	"multilang",
}

const (
	OrgActive     = "active"
	OrgInActive   = "inactive"
	OrgMass       = "mass"
	OrgEnterprise = "enterprise"
)

var ImmutableOrgs = []string{
	"root",
}

type OrgErrCode int

const (
	OrgErrEditRoot OrgErrCode = iota + 1
	OrgErrMultipleStatuses
	OrgErrStatusNotChanging
)
