package hash

import "regexp"

var (
	reMD4    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	reMD5    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	reSHA1   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	reSHA256 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	reSHA512 = regexp.MustCompile(`^[a-fA-F0-9]{128}$`)
)

func IsMD4(str string) bool {
	// Success
	return reMD4.MatchString(str)
}

func IsMD5(str string) bool {
	// Success
	return reMD5.MatchString(str)
}

func IsSHA1(str string) bool {
	// Success
	return reSHA1.MatchString(str)
}

func IsSHA256(str string) bool {
	// Success
	return reSHA256.MatchString(str)
}

func IsSHA512(str string) bool {
	// Success
	return reSHA512.MatchString(str)
}
