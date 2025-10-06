package helper

import (
	"net"
	"net/netip"
	"regexp"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
)

func GetAssetType(value string) string {
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

func IsIPv4(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	// Success
	return ip.Is4()
}

func IsIPv4CIDR(value string) bool {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return false
	}
	// Success
	return IsIPv4(network.IP.String())
}

func IsIPv6(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	// Success
	return ip.Is6()
}

func IsIPv6CIDR(value string) bool {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return false
	}
	// Success
	return IsIPv6(network.IP.String())
}

func IsIpPrivate(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		ip, _, _ = net.ParseCIDR(value)
		privateCIDRs := []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"127.0.0.0/8",
			"169.254.0.0/16",
			"::1/128",
			"fe80::/10",
			"fc00::/7",
		}

		for _, cidr := range privateCIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if ipnet.Contains(ip) {
				return true
			}
		}
		return false
	}

	// 10.0.0.0/8
	privateIpNet1 := net.IPNet{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.IPv4Mask(255, 0, 0, 0),
	}
	// 172.16.0.0/12
	privateIpNet2 := net.IPNet{
		IP:   net.ParseIP("172.16.0.0"),
		Mask: net.IPv4Mask(255, 240, 0, 0),
	}
	// 192.168.0.0/16
	privateIpNet3 := net.IPNet{
		IP:   net.ParseIP("192.168.0.0"),
		Mask: net.IPv4Mask(255, 255, 0, 0),
	}
	// 127.0.0.0/8 (Loopback)
	loopbackIpNetV4 := net.IPNet{
		IP:   net.ParseIP("127.0.0.0"),
		Mask: net.IPv4Mask(255, 0, 0, 0),
	}
	// 169.254.0.0/16 (Link-local APIPA)
	apipaIpNetV4 := net.IPNet{
		IP:   net.ParseIP("169.254.0.0"),
		Mask: net.IPv4Mask(255, 255, 0, 0),
	}

	// --- IPv6 Special-Use Ranges ---
	// fe80::/10 (Link-Local Unicast)
	_, linkLocalIpNetV6, _ := net.ParseCIDR("fe80::/10")
	// fc00::/7 (Unique Local Addresses - ULA)
	_, uniqueLocalIpNetV6, _ := net.ParseCIDR("fc00::/7")

	if ip.To4() != nil {
		if privateIpNet1.Contains(ip) ||
			privateIpNet2.Contains(ip) ||
			privateIpNet3.Contains(ip) ||
			loopbackIpNetV4.Contains(ip) ||
			apipaIpNetV4.Contains(ip) {
			return true
		}
	} else {
		if ip.Equal(net.ParseIP("::1")) {
			return true
		}
		if linkLocalIpNetV6 != nil && linkLocalIpNetV6.Contains(ip) {
			return true
		}
		if uniqueLocalIpNetV6 != nil && uniqueLocalIpNetV6.Contains(ip) {
			return true
		}
	}

	return false
}
