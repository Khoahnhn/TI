package model

import (
	"fmt"
	"strings"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/core/cpe"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
)

type (
	M                map[string]interface{}
	ProductAttribute struct {
		Vendor  string `json:"product_vendor"`
		Part    string `json:"product_part"`
		Product string `json:"product_product"`
		Version string `json:"product_version"`
		Update  string `json:"product_update"`
		Popular bool   `json:"popular"`
	}

	ProductPopular struct {
		ID      string `json:"id"`
		Created int64  `json:"created"`
		Value   string `json:"value"`
		Vendor  string `json:"vendor"`
		Part    string `json:"part"`
		Product string `json:"product"`
		Creator string `json:"creator"`
		Active  bool   `json:"active"`
	}

	ProductMapping struct {
		Organization string   `json:"organization"`
		Assets       []string `json:"assets"`
	}

	RequestAssetProductSearch struct {
		RequestOrganizationID
		Keyword string     `json:"keyword"`
		Part    []string   `json:"part"`
		Creator string     `json:"creator"`
		Active  string     `json:"active"`
		Time    RangeInt64 `json:"time"`
		Sorts   []string   `json:"sorts"`
		Offset  int        `json:"offset" validate:"numeric,gte=0"`
		Size    int        `json:"size" validate:"numeric,gte=0"`
	}

	RequestAssetProductStatistic struct {
		RequestOrganizationID
		Creator string `json:"creator" query:"creator"`
	}

	RequestAssetProductID struct {
		ID string `json:"id" param:"id" query:"id" validate:"required"`
	}

	RequestAssetProducts struct {
		RequestOrganizationID
		Products []string `json:"products" validate:"required"`
	}

	RequestAssetProductIDs struct {
		RequestOrganizationID
		IDs []string `json:"ids" validate:"required"`
	}

	RequestAssetProductCreate struct {
		RequestOrganizationID
		Products []string `json:"products" validate:"required"`
	}

	RequestAssetProductEdit struct {
		RequestAssetProductID
		RequestOrganizationID
		Product string `json:"product" query:"product" validate:"required"`
		Active  string `json:"active" query:"active"`
		Status  int    `json:"status" query:"status"`
	}

	ResponseSearchCPEPopular struct {
		Success bool             `json:"success"`
		Message string           `json:"message"`
		Detail  CPEPopularDetail `json:"detail"`
	}

	RequestAssetProductSynchronize struct {
		Creator string `json:"creator" query:"creator"`
	}

	CPEPopularDetail struct {
		Data  []ProductPopular `json:"data"`
		Total int64            `json:"total"`
	}
)

func (body RequestAssetProductSearch) Query() map[string]interface{} {
	filter := make([]interface{}, 0)
	filter = append(filter,
		map[string]interface{}{
			"term": map[string]interface{}{
				"visible": true,
			},
		},
		map[string]interface{}{
			"term": map[string]interface{}{
				"type": defs.AssetTypeProduct,
			},
		},
	)
	// Organization
	if query, ok := body.RequestOrganizationID.Query("organization"); ok {
		filter = append(filter, query)
	}
	// Keyword
	if body.Keyword != "" {
		should := make([]interface{}, 0)
		paths := strings.Split(body.Keyword, ":")
		switch len(paths) {
		case 2:
			filter = append(filter, map[string]interface{}{
				"wildcard": map[string]interface{}{
					"attribute.product_vendor": fmt.Sprintf("*%s*", paths[0]),
				},
			})
			should = append(
				should,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"attribute.product_product": fmt.Sprintf("*%s*", paths[1]),
					},
				},
			)
		case 3:
			filter = append(
				filter,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"attribute.product_vendor": fmt.Sprintf("*%s*", paths[0]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"attribute.product_product": fmt.Sprintf("*%s*", paths[1]),
					},
				},
			)
			should = append(should, map[string]interface{}{
				"wildcard": map[string]interface{}{
					"attribute.product_version": fmt.Sprintf("*%s*", paths[2]),
				},
			})
		case 4:
			filter = append(
				filter,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"attribute.product_vendor": fmt.Sprintf("*%s*", paths[0]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"attribute.product_product": fmt.Sprintf("*%s*", paths[1]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"attribute.product_version": fmt.Sprintf("*%s*", paths[2]),
					},
				},
			)
			should = append(should, map[string]interface{}{
				"wildcard": map[string]interface{}{
					"attribute.product_update": fmt.Sprintf("*%s*", paths[3]),
				},
			})
		default:
			should = append(
				should,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"attribute.product_vendor": fmt.Sprintf("*%s*", paths[0]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"attribute.product_product": fmt.Sprintf("*%s*", paths[0]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"attribute.product_version": fmt.Sprintf("*%s*", paths[0]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"attribute.product_update": fmt.Sprintf("*%s*", paths[0]),
					},
				},
			)
		}
		if len(should) > 0 {
			filter = append(filter, map[string]interface{}{
				"bool": map[string]interface{}{
					"should": should,
				},
			})
		}
	}
	// Part
	if len(body.Part) > 0 {
		should := make([]interface{}, 0)
		for _, part := range body.Part {
			should = append(should, map[string]interface{}{
				"term": map[string]interface{}{
					"attribute.product_part": part,
				},
			})
		}
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": should,
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
	// Active
	if value, ok := defs.MappingAssetActive[body.Active]; ok {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"active": value,
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
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": filter,
		},
	}
}

func (body RequestAssetProductSearch) Sort() []string {
	// Success
	if len(body.Sorts) == 0 {
		return []string{defs.DefaultSort}
	}
	return body.Sorts
}

func (body RequestAssetProductCreate) Generate(creator string) []*Asset {
	now, _ := clock.Now(clock.Local)
	nowTimestamp := clock.UnixMilli(now)
	documents := make([]*Asset, 0)
	for _, product := range body.Products {
		pro, _ := cpe.NewItemFromFormattedString(product)
		document := &Asset{
			Title:        product,
			Value:        product,
			Created:      nowTimestamp,
			Modified:     nowTimestamp,
			Type:         defs.AssetTypeProduct,
			Visible:      true,
			Active:       true,
			Status:       defs.AssetStatusCodeApproved,
			Creator:      creator,
			Organization: body.Organization,
			Attribute: ProductAttribute{
				Vendor:  pro.Vendor().String(),
				Part:    pro.Part().String(),
				Product: pro.Product().String(),
				Version: pro.Version().String(),
				Update:  pro.Update().String(),
			},
		}
		document.GenID()
		documents = append(documents, document)
	}
	// Success
	return documents
}
