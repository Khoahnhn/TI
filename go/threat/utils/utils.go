package utils

import (
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

func init() {
	structValidator = validator.New()
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
