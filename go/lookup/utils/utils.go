package utils

import (
	"math/big"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"ws-lookup/defs"

	"github.com/asaskevich/govalidator"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

func InferEntityType(value string) udm.EntityType {
	switch {
	case IsDomain(value):
		return udm.EntityTypeDomain
	case IsURL(value):
		return udm.EntityTypeURL
	case IsIP(value):
		return udm.EntityTypeIPAddress
	case IsSample(value):
		return udm.EntityTypeFile
	default:
		return ""
	}
}

func IsDomain(value string) bool {
	re := regexp.MustCompile(defs.RegexDomain)
	// Success
	return re.Match([]byte(value))
}

func IsURL(value string) bool {
	re := regexp.MustCompile(defs.RegexURL)
	// Success
	return re.Match([]byte(value))
}

func IsIP(value string) bool {
	// Success
	return IsIPv4(value) || IsIPv6(value)
}

func IsIPv4(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	// Success
	return ip.Is4()
}

func IsIPv6(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	// Success
	return ip.Is6()
}

func IsSample(value string) bool {
	switch {
	case IsMD5(value):
	case IsSHA1(value):
	case IsSHA256(value):
	case IsSHA512(value):
	default:
		return false
	}
	// Success
	return true
}

func IsMD5(value string) bool {
	// Success
	return govalidator.IsMD5(value)
}

func IsSHA1(value string) bool {
	// Success
	return govalidator.IsSHA1(value)
}

func IsSHA256(value string) bool {
	// Success
	return govalidator.IsSHA256(value)
}

func IsSHA512(value string) bool {
	// Success
	return govalidator.IsSHA512(value)
}

func IsCVE(value string) bool {
	re := regexp.MustCompile(defs.RegexCVE)
	// Success
	return re.Match([]byte(value))
}

func IPToInt(ip string, ipType udm.IPType) *big.Int {
	ipAddress := net.ParseIP(ip)
	switch ipType {
	case udm.IPTypeIPv4:
		parts := strings.Split(ipAddress.To4().String(), ".")
		partsInt := make([]int, len(parts))
		for i, part := range parts {
			partsInt[i], _ = strconv.Atoi(part)
		}
		return big.NewInt(int64(partsInt[0]<<24 | partsInt[1]<<16 | partsInt[2]<<8 | partsInt[3]))
	case udm.IPTypeIPv6:
		return big.NewInt(0).SetBytes(ipAddress)
	default:
		return big.NewInt(0)
	}
}

// Copied from https://stackoverflow.com/a/50825191
func IsPrivateIP(ip string) bool {
	ipAddress := net.ParseIP(ip)

	if ipAddress.IsLoopback() || ipAddress.IsLinkLocalUnicast() || ipAddress.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range defs.PrivateIPBlocks {
		if block.Contains(ipAddress) {
			return true
		}
	}
	// Success
	return false
}
