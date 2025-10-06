package resty

import (
	"crypto/tls"
	"fmt"
	"time"
	"ws-lookup/defs"
	"ws-lookup/model"

	"github.com/go-resty/resty/v2"
)

type client struct {
	con *resty.Client
}

func NewClient(conf model.RestyConfig) Client {
	timeout := conf.Timeout
	if timeout == 0 {
		timeout = defs.DefaultRestyTimeout
	}
	con := resty.New()
	con.SetTimeout(time.Duration(timeout) * time.Second)
	con.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: !conf.Secure})
	return &client{con: con}
}

func (inst *client) GetDomainPassiveDNS(enrichmentAPI string, domain string, limit int, offset int, result interface{}) (*resty.Response, error) {
	res, err := inst.con.R().
		SetBody(map[string]interface{}{
			"domain": domain,
			"size":   limit,
			"offset": offset,
		}).
		SetResult(&result).Post(fmt.Sprintf("%s/%s", enrichmentAPI, defs.RouteDomainPassiveDNS))
	if err != nil {
		return nil, err
	}
	// Success
	return res, nil
}

func (inst *client) GetIPAddressPassiveDNS(enrichmentAPI string, ipAddress string, limit int, offset int, result interface{}) (*resty.Response, error) {
	res, err := inst.con.R().
		SetBody(map[string]interface{}{
			"ipaddress": ipAddress,
			"size":      limit,
			"offset":    offset,
		}).
		SetResult(&result).Post(fmt.Sprintf("%s/%s", enrichmentAPI, defs.RouteIPAddressPassiveDNS))
	if err != nil {
		return nil, err
	}
	// Success
	return res, nil
}

func (inst *client) GetSubnet(enrichmentAPI string, ipAddress string, limit int, offset int, result interface{}) (*resty.Response, error) {
	res, err := inst.con.R().
		SetBody(map[string]interface{}{
			"ipaddress": ipAddress,
			"size":      limit,
			"offset":    offset,
		}).
		SetResult(&result).Post(fmt.Sprintf("%s/%s", enrichmentAPI, defs.RouteIPAddressSubnet))
	if err != nil {
		return nil, err
	}
	// Success
	return res, nil
}

func (inst *client) GetSubdomains(enrichmentAPI string, domain string, limit int, offset int, result interface{}) (*resty.Response, error) {
	res, err := inst.con.R().
		SetBody(map[string]interface{}{
			"domain": domain,
			"size":   limit,
			"offset": offset,
		}).
		SetResult(&result).Post(fmt.Sprintf("%s/%s", enrichmentAPI, defs.RouteDomainSubdomain))
	if err != nil {
		return nil, err
	}
	// Success
	return res, nil
}

func (inst *client) GetSiblingDomains(enrichmentAPI string, domain string, limit int, offset int, result interface{}) (*resty.Response, error) {
	res, err := inst.con.R().
		SetBody(map[string]interface{}{
			"domain": domain,
			"size":   limit,
			"offset": offset,
		}).
		SetResult(&result).Post(fmt.Sprintf("%s/%s", enrichmentAPI, defs.RouteDomainSibling))
	if err != nil {
		return nil, err
	}
	// Success
	return res, nil
}
