package defs

import "gitlab.viettelcyber.com/awesome-threat/library/core/cpe"

const (
	TypeCpe                    = "cpe"
	ProductTypeCodeApplication = "a"
	ProductTypeCodeHardware    = "h"
	ProductTypeCodeOperation   = "o"
	ProductTypeApplication     = "Application"
	ProductTypeHardWare        = "Hardware"
	ProductTypeOperatingSystem = "Operating System"
	KeyVendor                  = "vendor"
	KeyProduct                 = "product"
	KeyVersion                 = "version"
	KeyUpdate                  = "update"
	DefaultCreator             = "Unknown"
)

var (
	MappingProductType = map[string]string{
		ProductTypeCodeApplication: ProductTypeApplication,
		ProductTypeCodeHardware:    ProductTypeHardWare,
		ProductTypeCodeOperation:   ProductTypeOperatingSystem,
	}

	EnumCpePart = []string{
		ProductTypeCodeApplication,
		ProductTypeCodeHardware,
		ProductTypeCodeOperation,
	}

	MappingCPEPart = map[string]cpe.PartAttr{
		ProductTypeCodeApplication: cpe.Application,
		ProductTypeCodeHardware:    cpe.Hardware,
		ProductTypeCodeOperation:   cpe.OperationSystem,
	}
)
