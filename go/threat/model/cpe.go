package model

import (
	"fmt"
	"regexp"
	"strings"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/core/cpe"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
)

type CPERaw struct {
	Part       string   `json:"part"`
	References []string `json:"references"`
	SwEdition  string   `json:"sw_edition"`
	Version    string   `json:"version"`
	ID         string   `json:"id"`
	Created    int64    `json:"created"`
	Value      string   `json:"value"`
	Name       string   `json:"name"`
	Edition    string   `json:"edition"`
	Other      string   `json:"other"`
	Creator    string   `json:"creator"`
	Vendor     string   `json:"vendor"`
	Language   string   `json:"language"`
	Product    string   `json:"product"`
	Update     string   `json:"update"`
	TargetSw   string   `json:"target_sw"`
	TargetHw   string   `json:"target_hw"`
}

type (
	CPE struct {
		CPEDetail
		Name      string   `json:"name"`
		Edition   string   `json:"edition"`
		Language  string   `json:"language"`
		SwEdition string   `json:"sw_edition"`
		TargetSw  string   `json:"target_sw"`
		TargetHw  string   `json:"target_hw"`
		Other     string   `json:"other"`
		Reference []string `json:"references"`
	}

	CPEDetail struct {
		ID      string `json:"id"`
		Created int64  `json:"created"`
		Value   string `json:"value"`
		Vendor  string `json:"vendor"`
		Part    string `json:"part"`
		Product string `json:"product"`
		Version string `json:"version"`
		Update  string `json:"update"`
		Creator string `json:"creator"`
	}

	CPEDetails []*CPEDetail

	CPEMeta struct {
		CPE
		Metadata Metadata `json:"@metadata"`
	}

	CPEPopular struct {
		ID      string `json:"id"`
		Created int64  `json:"created"`
		Value   string `json:"value"`
		Vendor  string `json:"vendor"`
		Part    string `json:"part"`
		Product string `json:"product"`
		Creator string `json:"creator"`
		Active  bool   `json:"active"`
	}

	RequestCPEIDs struct {
		IDs []string `json:"ids" validate:"required"`
	}

	RequestCPESearch struct {
		Keyword string     `json:"keyword"`
		Creator string     `json:"creator"`
		Part    []string   `json:"part"`
		Time    RangeInt64 `json:"time"`
		Sort    []string   `json:"sort"`
		Size    int        `json:"size" validate:"numeric"`
		Offset  int        `json:"offset" validate:"numeric"`
	}

	RequestCPEQuery struct {
		Query  string `json:"q" query:"q"`
		Size   int    `json:"size" query:"size" validate:"numeric"`
		Offset int    `json:"offset" query:"offset" validate:"numeric"`
	}

	RequestCPESuggestVendor struct {
		RequestCPEQuery
	}

	RequestCPESuggestProduct struct {
		RequestCPEQuery
		Vendor string `json:"vendor" query:"vendor"`
		Part   string `json:"part" query:"part"`
	}

	RequestCPESuggestVersion struct {
		RequestCPESuggestProduct
		Product string `json:"product" query:"product" validate:"required"`
	}

	RequestCPESuggestUpdate struct {
		RequestCPESuggestVersion
		Version string `json:"version" query:"version" validate:"required"`
	}

	RequestCPEStatistic struct {
		Creator string `json:"creator" query:"creator"`
	}

	RequestCPECreate struct {
		Vendor  string `json:"vendor" query:"vendor" validate:"required"`
		Part    string `json:"part" query:"part" validate:"required"`
		Product string `json:"product" query:"product" validate:"required"`
		Version string `json:"version" query:"version"`
		Update  string `json:"update" query:"update"`
	}

	RequestCPEPopularCreate struct {
		Vendor  string `json:"vendor" validate:"required"`
		Part    string `json:"part" validate:"required"`
		Product string `json:"product"`
	}
)

func NewCPE(cpe string) *CPEMeta {
	now, _ := clock.Now(clock.UTC)
	data := strings.Split(cpe, ":")
	if len(data) < 13 {
		return nil
	}
	titleSplit := make([]string, 0)
	for i := 3; i < len(data); i++ {
		if data[i] != "*" {
			titleSplit = append(titleSplit, data[i])
		}
	}
	cpeID := hash.SHA1(cpe)
	document := CPEMeta{
		CPE: CPE{
			CPEDetail: CPEDetail{
				ID:      cpeID,
				Created: clock.UnixMilli(now),
				Value:   cpe,
				Part:    data[2],
				Vendor:  data[3],
				Product: data[4],
				Version: data[5],
				Update:  data[6],
				Creator: defs.DefaultCreator,
			},
			Name:      strings.Join(titleSplit, " "),
			Edition:   data[7],
			Language:  data[8],
			SwEdition: data[9],
			TargetSw:  data[10],
			TargetHw:  data[11],
			Other:     data[12],
			Reference: make([]string, 0),
		},
		Metadata: Metadata{
			Index: defs.IndexCpe,
			Type:  defs.TypeCpe,
			ID:    cpeID,
		},
	}
	// Success
	return &document
}

func (doc *CPE) GetID() string {
	// Success
	return doc.ID
}

func (doc *CPE) SetEID(id string) {
	// Success
	doc.ID = id
}

func (doc *CPE) Apply(value cpe.Item) {
	// Properties
	doc.Vendor = value.Vendor().String()
	doc.Part = value.Part().String()
	doc.Product = value.Product().String()
	doc.Version = value.Version().String()
	doc.Update = value.Update().String()
	doc.Edition = value.Edition().String()
	doc.Language = value.Language().String()
	doc.SwEdition = value.SwEdition().String()
	doc.TargetSw = value.TargetSw().String()
	doc.TargetHw = value.TargetHw().String()
	doc.Other = value.Other().String()
	// Value
	doc.Value = value.Formatted()
	doc.Name = strings.Join([]string{doc.Vendor, doc.Product, doc.Version}, " ")
	doc.ID = hash.SHA1(doc.Value)
}

func (doc *CPEPopular) GetID() string {
	// Success
	return doc.ID
}

func (doc *CPEPopular) SetEID(id string) {
	// Success
	doc.ID = id
}

func (doc *CPEPopular) GenID() {
	// Success
	doc.ID = hash.SHA1(doc.Value)
}

func (doc *CPEDetail) GetID() string {
	// Success
	return doc.ID
}

func (doc CPEDetails) Len() int {
	// Success
	return len(doc)
}

func (doc CPEDetails) Less(i, j int) bool {
	// Success
	return doc[i].Value < doc[j].Value
}

func (doc CPEDetails) Swap(i, j int) {
	// Success
	doc[i], doc[j] = doc[j], doc[i]
}

func (body *RequestCPESuggestVendor) PrepareQuery() map[string]interface{} {
	filter := make([]interface{}, 0)
	if body.Query != "" {
		filter = append(filter, map[string]interface{}{
			"wildcard": map[string]interface{}{
				"vendor": fmt.Sprintf("*%s*", regexp.QuoteMeta(body.Query)),
			},
		})
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

func (body *RequestCPESuggestProduct) PrepareQuery() map[string]interface{} {
	filter := make([]interface{}, 0)
	if strings.Contains(body.Vendor, ",") {
		vendorFilter := make([]interface{}, 0)
		vendors := strings.Split(body.Vendor, ",")
		for _, vendor := range vendors {
			vendorFilter = append(vendorFilter, map[string]interface{}{
				"term": map[string]interface{}{
					"vendor": vendor,
				},
			})
		}
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": vendorFilter,
			},
		})
	} else {
		filter = append(filter,
			map[string]interface{}{
				"term": map[string]interface{}{
					"vendor": body.Vendor,
				},
			},
		)
	}
	if body.Part != "" {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"part": body.Part,
			},
		})
	}
	if body.Query != "" {
		should := make([]interface{}, 0)
		paths := strings.Split(body.Query, ":")
		switch len(paths) {
		case 2:
			filter = append(filter, map[string]interface{}{
				"term": map[string]interface{}{
					"product": paths[0],
				},
			})
			should = append(
				should,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"version": fmt.Sprintf("*%s*", regexp.QuoteMeta(paths[1])),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"update": fmt.Sprintf("*%s*", regexp.QuoteMeta(paths[1])),
					},
				},
			)
		case 3:
			filter = append(
				filter,
				map[string]interface{}{
					"term": map[string]interface{}{
						"product": paths[0],
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"version": paths[1],
					},
				},
			)
			should = append(should, map[string]interface{}{
				"wildcard": map[string]interface{}{
					"update": fmt.Sprintf("*%s*", regexp.QuoteMeta(paths[2])),
				},
			})
		default:
			should = append(
				should,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"product": fmt.Sprintf("*%s*", regexp.QuoteMeta(body.Query)),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"version": fmt.Sprintf("*%s*", regexp.QuoteMeta(body.Query)),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"update": fmt.Sprintf("*%s*", regexp.QuoteMeta(body.Query)),
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

func (body *RequestCPESuggestVersion) PrepareQuery() map[string]interface{} {
	filter := make([]interface{}, 0)
	if strings.Contains(body.Vendor, ",") {
		vendorFilter := make([]interface{}, 0)
		vendors := strings.Split(body.Vendor, ",")
		for _, vendor := range vendors {
			vendorFilter = append(vendorFilter, map[string]interface{}{
				"term": map[string]interface{}{
					"vendor": vendor,
				},
			})
		}
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": vendorFilter,
			},
		})
	} else {
		filter = append(filter,
			map[string]interface{}{
				"term": map[string]interface{}{
					"vendor": body.Vendor,
				},
			},
		)
	}
	filter = append(filter,
		map[string]interface{}{
			"term": map[string]interface{}{
				"product": body.Product,
			},
		},
	)
	if body.Part != "" {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"part": body.Part,
			},
		})
	}
	if body.Query != "" {
		should := make([]interface{}, 0)
		paths := strings.Split(body.Query, ":")
		switch len(paths) {
		case 2:
			filter = append(filter, map[string]interface{}{
				"term": map[string]interface{}{
					"version": paths[0],
				},
			})
			should = append(
				should,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"update": fmt.Sprintf("*%s*", regexp.QuoteMeta(paths[1])),
					},
				},
			)
		default:
			should = append(
				should,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"version": fmt.Sprintf("*%s*", regexp.QuoteMeta(body.Query)),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"update": fmt.Sprintf("*%s*", regexp.QuoteMeta(body.Query)),
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

func (body *RequestCPESuggestUpdate) PrepareQuery() map[string]interface{} {
	filter := make([]interface{}, 0)
	if strings.Contains(body.Vendor, ",") {
		vendorFilter := make([]interface{}, 0)
		vendors := strings.Split(body.Vendor, ",")
		for _, vendor := range vendors {
			vendorFilter = append(vendorFilter, map[string]interface{}{
				"term": map[string]interface{}{
					"vendor": vendor,
				},
			})
		}
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": vendorFilter,
			},
		})
	} else {
		filter = append(filter,
			map[string]interface{}{
				"term": map[string]interface{}{
					"vendor": body.Vendor,
				},
			},
		)
	}
	filter = append(filter,
		map[string]interface{}{
			"term": map[string]interface{}{
				"product": body.Product,
			},
		},
		map[string]interface{}{
			"term": map[string]interface{}{
				"version": body.Version,
			},
		},
	)
	if body.Part != "" {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"part": body.Part,
			},
		})
	}
	if body.Query != "" {
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []interface{}{
					map[string]interface{}{
						"wildcard": map[string]interface{}{
							"update": fmt.Sprintf("*%s*", regexp.QuoteMeta(body.Query)),
						},
					},
				},
			},
		})
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

func (body *RequestCPESearch) PrepareQuery() map[string]interface{} {
	filter := make([]interface{}, 0)
	if body.Keyword != "" {
		should := make([]interface{}, 0)
		paths := strings.Split(body.Keyword, ":")
		switch len(paths) {
		case 2:
			filter = append(filter, map[string]interface{}{
				"wildcard": map[string]interface{}{
					"vendor": fmt.Sprintf("*%s*", paths[0]),
				},
			})
			should = append(
				should,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"product": fmt.Sprintf("*%s*", paths[1]),
					},
				},
			)
		case 3:
			filter = append(
				filter,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"vendor": fmt.Sprintf("*%s*", paths[0]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"product": fmt.Sprintf("*%s*", paths[1]),
					},
				},
			)
			should = append(should, map[string]interface{}{
				"wildcard": map[string]interface{}{
					"version": fmt.Sprintf("*%s*", paths[2]),
				},
			})
		case 4:
			filter = append(
				filter,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"vendor": fmt.Sprintf("*%s*", paths[0]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"product": fmt.Sprintf("*%s*", paths[1]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"version": fmt.Sprintf("*%s*", paths[2]),
					},
				},
			)
			should = append(should, map[string]interface{}{
				"wildcard": map[string]interface{}{
					"update": fmt.Sprintf("*%s*", paths[3]),
				},
			})
		default:
			should = append(
				should,
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"vendor": fmt.Sprintf("*%s*", paths[0]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"product": fmt.Sprintf("*%s*", paths[0]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"version": fmt.Sprintf("*%s*", paths[0]),
					},
				},
				map[string]interface{}{
					"wildcard": map[string]interface{}{
						"update": fmt.Sprintf("*%s*", paths[0]),
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
	if len(body.Part) > 0 {
		should := make([]interface{}, 0)
		for _, part := range body.Part {
			should = append(should, map[string]interface{}{
				"term": map[string]interface{}{
					"part": part,
				},
			})
		}
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": should,
			},
		})
	}
	createdFilter := map[string]interface{}{}
	if body.Time.Gte > 0 {
		gte, _ := clock.ParseMilliTimestamp(body.Time.Gte, clock.Local)
		createdFilter["gte"] = clock.UnixMilli(gte)
	}
	if body.Time.Lte > 0 {
		lte, _ := clock.ParseMilliTimestamp(body.Time.Lte, clock.Local)
		createdFilter["lte"] = clock.UnixMilli(lte)
	}
	if len(createdFilter) > 0 {
		filter = append(filter, map[string]interface{}{"range": map[string]interface{}{"created": createdFilter}})
	}
	// Creator
	if body.Creator != "" {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"creator": body.Creator,
			},
		})
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

func (body *RequestCPEPopularCreate) PrepareQuery() map[string]interface{} {
	filter := make([]interface{}, 0)
	filter = append(
		filter,
		map[string]interface{}{
			"wildcard": map[string]interface{}{
				"vendor": body.Vendor,
			},
		},
		map[string]interface{}{
			"term": map[string]interface{}{
				"part": body.Part,
			},
		},
		map[string]interface{}{
			"wildcard": map[string]interface{}{
				"product": body.Product,
			},
		},
	)
	// Success
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": filter,
		},
	}
}
