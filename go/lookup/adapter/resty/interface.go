package resty

import (
	"github.com/go-resty/resty/v2"
)

type Client interface {
	GetDomainPassiveDNS(enrichmentAPI string, domain string, limit int, offset int, result interface{}) (*resty.Response, error)
	GetIPAddressPassiveDNS(enrichmentAPI string, ipAddress string, limit int, offset int, result interface{}) (*resty.Response, error)
	GetSubnet(enrichmentAPI string, ipAddress string, limit int, offset int, result interface{}) (*resty.Response, error)
	GetSubdomains(enrichmentAPI string, domain string, limit int, offset int, result interface{}) (*resty.Response, error)
	GetSiblingDomains(enrichmentAPI string, domain string, limit int, offset int, result interface{}) (*resty.Response, error)
}
