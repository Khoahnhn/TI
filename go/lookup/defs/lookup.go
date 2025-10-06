package defs

import (
	"fmt"
	"net"
)

type (
	StatusIOC string
)

func init() {
	for _, cidr := range PrivateCIDR {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("failed to parse private cidr %s: %v", cidr, err))
		}
		PrivateIPBlocks = append(PrivateIPBlocks, block)
	}
}

var (
	StatusIOCUnknown   StatusIOC = "unknown"
	StatusIOCWhitelist StatusIOC = "whitelist"
	StatusIOCExclusive StatusIOC = "exclusive"
)

var (
	SectionPopularityRank = "popularity_rank"
	SectionWhois          = "whois"
	SectionPassiveDNS     = "passive_dns"
	SectionDNSRecord      = "dns_record"
	SectionHash           = "hash"
	SectionSubdomains     = "subdomain"
	SectionSiblings       = "sibling_domain"
	SectionSSLCertificate = "ssl_certificate"
	SectionRelations      = "relations"
	SectionSecurityResult = "security_result"
	SectionArtifact       = "artifact"
	SectionSubnet         = "subnet"
	SectionHTTPRequest    = "http_request"
)

var (
	EnumSectionDomain = map[string]bool{
		SectionPopularityRank: true,
		SectionWhois:          true,
		SectionPassiveDNS:     true,
		SectionDNSRecord:      true,
		SectionHash:           true,
		SectionSubdomains:     true,
		SectionSiblings:       true,
		SectionSSLCertificate: true,
		SectionRelations:      true,
		SectionSecurityResult: true,
		SectionHTTPRequest:    true,
	}

	EnumSectionIPAddress = map[string]bool{
		SectionArtifact:       true,
		SectionPassiveDNS:     true,
		SectionHash:           true,
		SectionSubnet:         true,
		SectionSSLCertificate: true,
		SectionRelations:      true,
		SectionSecurityResult: true,
	}

	EnumSectionURL = map[string]bool{
		SectionHTTPRequest:    true,
		SectionWhois:          true,
		SectionPassiveDNS:     true,
		SectionDNSRecord:      true,
		SectionHash:           true,
		SectionSubdomains:     true,
		SectionSiblings:       true,
		SectionSSLCertificate: true,
		SectionRelations:      true,
		SectionSecurityResult: true,
	}

	EnumSectionFile = map[string]bool{
		SectionSecurityResult: true,
	}
)

var (
	PrivateCIDR = []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	}
	PrivateIPBlocks = []*net.IPNet{}
)
