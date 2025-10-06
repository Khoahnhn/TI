package defs

import "gitlab.viettelcyber.com/awesome-threat/library/core/cpe"

const (
	// Asset status
	AssetStatusCodeUnknown  = 0
	AssetStatusCodeNew      = 1
	AssetStatusCodeApproved = 2
	AssetStatusCodeReject   = 3
	AssetStatusUnknown      = "Unknown"
	AssetStatusNew          = "New"
	AssetStatusApproved     = "Approved"
	AssetStatusReject       = "Reject"
	// Asset type
	AssetTypeUnknown     = "unknown"
	AssetTypeDomain      = "domain"
	AssetTypeIPv4        = "ipv4"
	AssetTypeIPv6        = "ipv6"
	AssetTypeIPv4Network = "ipv4-network"
	AssetTypeIPv6Network = "ipv6-network"
	AssetTypeProduct     = "product"
	AssetTypeIpPrivate   = "ip-private"
	// Asset active
	AssetActive   = "active"
	AssetInactive = "inactive"
	// Asset product part
	ProductPartCodeApplication = "a"
	ProductPartCodeHardware    = "h"
	ProductPartCodeOperation   = "o"
	ProductPartApplication     = "Application"
	ProductPartHardWare        = "Hardware"
	ProductPartOperation       = "Operation"
	// Regex
	DefaultDomainRegex = "wildcard"
	RegexMatchDomain   = `^(.*?\.)?%s$`
	// Action
	ActionActive        = "active"
	ActionDeactive      = "inactive"
	ActionApprove       = "approve"
	ActionReject        = "reject"
	ActionDelete        = "delete"
	TitleActionCreate   = "Create Asset"
	TitleActionEdit     = "Edit Asset"
	TitleActionActive   = "Active Asset"
	TitleActionDeactive = "Deactive Asset"
	TitleActionApprove  = "Approve Asset"
	TitleActionReject   = "Reject Asset"
	TitleActionDelete   = "Delete Asset"
)

var (
	EnumAssetType                = []string{AssetTypeDomain, AssetTypeIPv4, AssetTypeIPv6, AssetTypeIPv4Network, AssetTypeIPv6Network, AssetTypeProduct}
	EnumAssetDomainIPAddressType = []string{AssetTypeDomain, AssetTypeIPv4, AssetTypeIPv6, AssetTypeIPv4Network, AssetTypeIPv6Network}
	EnumAction                   = []string{ActionActive, ActionDeactive, ActionApprove, ActionReject, ActionDelete}

	MappingActionTitle = map[string]string{
		ActionActive:   TitleActionActive,
		ActionDeactive: TitleActionDeactive,
		ActionApprove:  TitleActionApprove,
		ActionReject:   TitleActionReject,
		ActionDelete:   TitleActionDelete,
	}
	MappingAssetStatus = map[int]string{
		AssetStatusCodeNew:      AssetStatusNew,
		AssetStatusCodeApproved: AssetStatusApproved,
		AssetStatusCodeReject:   AssetStatusReject,
	}
	MappingAssetActive = map[string]bool{
		AssetActive:   true,
		AssetInactive: false,
	}
	MappingProductPart = map[string]string{
		ProductPartCodeApplication: ProductPartApplication,
		ProductPartCodeHardware:    ProductPartHardWare,
		ProductPartCodeOperation:   ProductPartOperation,
	}

	MappingAssetType = map[string]string{
		AssetTypeUnknown:     "Unknown",
		AssetTypeDomain:      "Domain",
		AssetTypeIPv4:        "IPv4",
		AssetTypeIPv4Network: "IPv4 Network",
		AssetTypeIPv6:        "IPv6",
		AssetTypeIPv6Network: "IPv6 Network",
		AssetTypeProduct:     "Product",
		AssetTypeIpPrivate:   "IP Private",
	}
	MappingProductType = map[string]string{
		"a":                "a",
		"h":                "h",
		"o":                "o",
		"application":      "a",
		"hardware":         "h",
		"operating system": "o",
	}

	MappingCPEProductPart = map[string]cpe.PartAttr{
		"a": cpe.Application,
		"h": cpe.Hardware,
		"o": cpe.OperationSystem,
	}
)
