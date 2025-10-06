package model

import (
	"fmt"
	"net"
	"strings"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/helper"
)

type (
	DomainAttribute struct {
		TLD    string `json:"tld"`
		Root   string `json:"root"`
		Domain string `json:"domain"`
		Regex  string `json:"regex"`
		Match  string `json:"match"`
	}

	IPv4Attribute struct {
		IPAddress string `json:"ipaddress"`
	}

	IPv4NetworkAttribute struct {
		Network string `json:"network"`
		Mask    string `json:"mask"`
	}

	IPv6Attribute struct {
		IPAddress string `json:"ipaddress"`
	}

	IPv6NetworkAttribute struct {
		Network string `json:"network"`
		Mask    string `json:"mask"`
	}

	RequestAssetDomainIPAddressID struct {
		ID string `json:"id" param:"id" query:"id" validate:"required"`
	}

	RequestAssetDomainIPAddress struct {
		RequestOrganizationID
		Assets []string `json:"assets" validate:"required"`
	}

	RequestAssetDomainIPAddressSearch struct {
		RequestOrganizationID
		Keyword string     `json:"keyword"`
		Creator string     `json:"creator"`
		Type    []string   `json:"type"`
		Active  string     `json:"active"`
		Status  []int      `json:"status"`
		Time    RangeInt64 `json:"time"`
		Sorts   []string   `json:"sorts"`
		Offset  int        `json:"offset" validate:"numeric,gte=0"`
		Size    int        `json:"size" validate:"numeric,gte=0"`
		Tags    []string   `json:"tags" mod:"dive,trim,lcase"`
	}

	RequestAssetDomainIPAddressStatistic struct {
		RequestOrganizationID
		Creator string   `json:"creator" query:"creator"`
		Tags    []string `json:"tags" query:"tags" mod:"dive,trim,lcase"`
	}

	RequestAssetDomainIPAddressCreate struct {
		RequestOrganizationID
		Active bool     `json:"active"`
		Assets []string `json:"assets" validate:"required"`
		Tags   []string `json:"tags" mod:"dive,trim,lcase"`
	}

	RequestAssetDomainIPAddressEdit struct {
		RequestAssetDomainIPAddressID
		RequestOrganizationID
		Asset  string   `json:"asset" query:"asset" validate:"required"`
		Active string   `json:"active" query:"active"`
		Status int      `json:"status" query:"status"`
		Tags   []string `json:"tags" mod:"dive,trim,lcase"`
	}

	RequestAssetDomainIPAddressValue struct {
		Asset string `json:"asset" param:"asset" query:"asset" validate:"required"`
	}

	RequestAssetDomainIPAddressDelete struct {
		IDs []string `json:"ids" validate:"required"`
	}
)

func (body RequestAssetDomainIPAddressSearch) Query() map[string]interface{} {
	filter := make([]interface{}, 0)
	filter = append(filter, map[string]interface{}{
		"term": map[string]interface{}{
			"visible": true,
		},
	})
	// Organization
	if query, ok := body.RequestOrganizationID.Query("organization"); ok {
		filter = append(filter, query)
	}
	// Keyword
	if body.Keyword != "" {
		wildcard := fmt.Sprintf("*%s*", body.Keyword)
		filter = append(filter, map[string]interface{}{
			"wildcard": map[string]interface{}{
				"value": wildcard,
			},
		})
	}
	// Creator
	if body.Creator != "" {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"creator": body.Creator,
			},
		})
	}
	// Type
	if len(body.Type) > 0 {
		should := make([]interface{}, 0)
		for _, t := range body.Type {
			should = append(should, map[string]interface{}{
				"term": map[string]interface{}{
					"type": t,
				},
			})
		}
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": should,
			},
		})
	}
	// Active
	if value, ok := defs.MappingAssetActive[body.Active]; ok {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"active": value,
			},
		})
	}
	// Status
	if len(body.Status) > 0 {
		should := make([]interface{}, 0)
		for _, status := range body.Status {
			should = append(should, map[string]interface{}{
				"term": map[string]interface{}{
					"status": status,
				},
			})
		}
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": should,
			},
		})
	}
	// Time
	if query, ok := body.Time.Query("modified"); ok {
		filter = append(filter, query)
	}
	// Success
	if len(filter) == 0 {
		return defs.ElasticsearchQueryFilterMatchAll
	}
	// Tags
	if len(body.Tags) > 0 {
		filter = append(filter, map[string]interface{}{
			"terms": map[string]interface{}{
				"tags": body.Tags,
			},
		})
	}
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": filter,
		},
	}
}

func (body RequestAssetDomainIPAddressSearch) Sort() []string {
	// Success
	if len(body.Sorts) == 0 {
		return []string{defs.DefaultSort}
	}
	return body.Sorts
}

func (body RequestAssetDomainIPAddressCreate) Generate(creator string) []*Asset {
	now, _ := clock.Now(clock.Local)
	nowTimestamp := clock.UnixMilli(now)
	documents := make([]*Asset, 0)
	for _, asset := range body.Assets {
		kind := helper.GetAssetType(asset)
		if kind == "" {
			continue
		}
		document := &Asset{
			Title:        asset,
			Value:        asset,
			Created:      nowTimestamp,
			Modified:     nowTimestamp,
			Type:         kind,
			Visible:      true,
			Active:       body.Active,
			Status:       defs.AssetStatusCodeNew,
			Creator:      creator,
			Organization: body.Organization,
			Tags:         body.Tags,
		}
		document.GenID()
		document.Attribute = GenerateDomainIPAddressAttribute(kind, asset)
		documents = append(documents, document)
	}
	// Success
	return documents
}

func (body RequestAssetDomainIPAddressValue) Query() map[string]interface{} {
	kind := helper.GetAssetType(body.Asset)
	filter := make([]interface{}, 0)
	filter = append(filter,
		map[string]interface{}{
			"term": map[string]interface{}{
				"status": defs.AssetStatusCodeApproved,
			},
		},
		map[string]interface{}{
			"term": map[string]interface{}{
				"active": true,
			},
		},
		map[string]interface{}{
			"term": map[string]interface{}{
				"visible": true,
			},
		},
	)
	switch kind {
	case defs.AssetTypeIPv4, defs.AssetTypeIPv6:
		should := make([]interface{}, 0)
		should = append(should,
			map[string]interface{}{
				"term": map[string]interface{}{
					"type": defs.AssetTypeIPv4,
				},
			},
			map[string]interface{}{
				"term": map[string]interface{}{
					"type": defs.AssetTypeIPv4Network,
				},
			},
			map[string]interface{}{
				"term": map[string]interface{}{
					"type": defs.AssetTypeIPv6,
				},
			},
			map[string]interface{}{
				"term": map[string]interface{}{
					"type": defs.AssetTypeIPv6Network,
				},
			},
		)
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": should,
			},
		})
	case defs.AssetTypeIPv4Network, defs.AssetTypeIPv6Network:
		should := make([]interface{}, 0)
		should = append(should,
			map[string]interface{}{
				"term": map[string]interface{}{
					"type": defs.AssetTypeIPv4Network,
				},
			},
			map[string]interface{}{
				"term": map[string]interface{}{
					"type": defs.AssetTypeIPv6Network,
				},
			},
		)
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": should,
			},
		})
	case defs.AssetTypeDomain:
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"type": defs.AssetTypeDomain,
			},
		})
	default:
		return nil
	}
	// Success
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": filter,
		},
	}
}

func GenerateDomainIPAddressAttribute(kind, asset string) interface{} {
	switch kind {
	case defs.AssetTypeIPv4:
		ip := net.ParseIP(asset)
		if ip != nil {
			return IPv4Attribute{IPAddress: ip.String()}
		} else {
			return map[string]interface{}{}
		}
	case defs.AssetTypeIPv4Network:
		_, ipNet, err := net.ParseCIDR(asset)
		if err == nil {
			mask := ipNet.Mask
			return IPv4NetworkAttribute{
				Network: fmt.Sprintf("%+v", ipNet.IP),
				Mask:    fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]),
			}
		} else {
			return map[string]interface{}{}
		}
	case defs.AssetTypeIPv6:
		ip := net.ParseIP(asset)
		if ip != nil {
			return IPv6Attribute{IPAddress: ip.String()}
		} else {
			return map[string]interface{}{}
		}
	case defs.AssetTypeIPv6Network:
		_, ipNet, err := net.ParseCIDR(asset)
		if err == nil {
			mask := ipNet.Mask
			return IPv6NetworkAttribute{
				Network: fmt.Sprintf("%+v", ipNet.IP),
				Mask:    fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", mask[0], mask[1], mask[2], mask[3], mask[4], mask[5], mask[6], mask[7], mask[8], mask[9], mask[10], mask[11], mask[12], mask[13], mask[14], mask[15]),
			}
		} else {
			return map[string]interface{}{}
		}
	case defs.AssetTypeDomain:
		result := helper.ExtractDomain(asset)
		if result.Tld != "" && result.Root != "" {
			return DomainAttribute{
				TLD:    result.Tld,
				Root:   fmt.Sprintf("%s.%s", result.Root, result.Tld),
				Domain: asset,
				Regex:  defs.DefaultDomainRegex,
				Match:  fmt.Sprintf(defs.RegexMatchDomain, strings.ReplaceAll(asset, ".", "\\.")),
			}
		} else {
			return map[string]interface{}{}
		}
	default:
		return map[string]interface{}{}
	}
}
