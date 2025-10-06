package utils

import (
	"regexp"

	"github.com/go-playground/validator/v10"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
)

var (
	structValidator *validator.Validate
)

type (
	IPv4Validator struct {
		Value string `validate:"required,ipv4"`
	}

	IPv4CIDRValidator struct {
		Value string `validate:"required,cidrv4"`
	}

	IPv6Validator struct {
		Value string `validate:"required,ipv6"`
	}

	IPv6CIDRValidator struct {
		Value string `validate:"required,cidrv6"`
	}
)

func GetType(value string) string {
	verbose := GetVerbose(value)
	if verbose != "" {
		if kind, ok := defs.MappingIndicatorType[verbose]; ok {
			return kind
		}
	}
	return defs.TypeUnknown
}

func GetVerbose(value string) string {
	if IsIPv4(value) {
		return defs.AssetTypeIPv4
	}
	if IsIPv4CIDR(value) {
		return defs.AssetTypeIPv4Network
	}
	if IsIPv6(value) {
		return defs.AssetTypeIPv6
	}
	if IsIPv6CIDR(value) {
		return defs.AssetTypeIPv6Network
	}
	if IsEmail(value) {
		return defs.AssetTypeEmail
	}
	if IsURL(value) {
		return defs.AssetTypeURL
	}
	if IsSampleSHA512(value) {
		return defs.AssetTypeSampleSHA512
	}
	if IsSampleSHA256(value) {
		return defs.AssetTypeSampleSHA256
	}
	if IsSampleSHA1(value) {
		return defs.AssetTypeSampleSHA1
	}
	if IsSampleMD5(value) {
		return defs.AssetTypeSampleSHA1
	}
	if IsDomain(value) {
		return defs.AssetTypeDomain
	}
	// Not found
	return ""
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

func IsEmail(value string) bool {
	re := regexp.MustCompile(defs.RegexEmail)
	// Success
	return re.Match([]byte(value))
}

func IsSampleMD5(value string) bool {
	re := regexp.MustCompile(defs.RegexSampleMD5)
	// Success
	return re.Match([]byte(value))
}

func IsSampleSHA1(value string) bool {
	re := regexp.MustCompile(defs.RegexSampleSHA1)
	// Success
	return re.Match([]byte(value))
}

func IsSampleSHA256(value string) bool {
	re := regexp.MustCompile(defs.RegexSampleSHA256)
	// Success
	return re.Match([]byte(value))
}

func IsSampleSHA512(value string) bool {
	re := regexp.MustCompile(defs.RegexSampleSHA512)
	// Success
	return re.Match([]byte(value))
}

func IsIPv4(value string) bool {
	// Success
	return structValidator.Struct(IPv4Validator{Value: value}) == nil
}

func IsIPv4CIDR(value string) bool {
	// Success
	return structValidator.Struct(IPv4CIDRValidator{Value: value}) == nil
}

func IsIPv6(value string) bool {
	// Success
	return structValidator.Struct(IPv6Validator{Value: value}) == nil
}

func IsIPv6CIDR(value string) bool {
	// Success
	return structValidator.Struct(IPv6CIDRValidator{Value: value}) == nil
}
