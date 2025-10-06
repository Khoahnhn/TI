package model

import (
	"fmt"
	"regexp"
	"strings"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
)

type (
	IOC struct {
		ID          string       `json:"id"`
		Label       string       `json:"label"`
		Created     string       `json:"creation_date"`
		Modified    string       `json:"updated_date"`
		Source      []string     `json:"source"`
		Type        string       `json:"type"`
		Malicious   int          `json:"malicious"`
		MalwareName string       `json:"malware_name"`
		Categories  []string     `json:"categories"`
		Ranking     int          `json:"ranking"`
		Attribute   IOCAttribute `json:"attribute"`
		ReportLink  []string     `json:"report_link"`
	}

	IOCAttribute struct {
		Tags  []string `json:"tags"`
		Regex string   `json:"regex"`
	}

	IOCDetail struct {
		Label string `json:"label"`
		Type  string `json:"type"`
	}

	IOCHistory struct {
		ID      string `json:"id"`
		Created int64  `json:"created"`
		IOC     string `json:"ioc"`
		Creator string `json:"creator"`
		Action  string `json:"action"`
		Comment string `json:"comment"`
	}

	RequestIOCSearch struct {
		Keyword    string     `json:"keyword"`
		Tags       []string   `json:"tags"`
		Categories []string   `json:"categories"`
		Types      []string   `json:"types"`
		Status     []int      `json:"status"`
		Created    RangeInt64 `json:"created"`
		Modified   RangeInt64 `json:"modified"`
		Sorts      []string   `json:"sorts"`
		Offset     int        `json:"offset"`
		Size       int        `json:"size"`
	}

	RequestIOCID struct {
		ID string `json:"id" param:"id" validate:"required"`
	}

	RequestIOCCreate struct {
		Data        []IOCDetail `json:"data" validate:"required"`
		Source      string      `json:"source"`
		Regex       string      `json:"regex"`
		Categories  []string    `json:"categories" validate:"required"`
		MalwareName string      `json:"malware_name" validate:"required"`
		Tags        []string    `json:"tags"`
		Creator     string      `json:"creator"`
		Comment     string      `json:"comment"`
		ReportLink  []string    `json:"report_link"`
		Status      int         `json:"status"`
	}

	RequestIOCEdit struct {
		RequestIOCID
		Status      int      `json:"status"`
		Regex       string   `json:"regex" validate:"required"`
		Categories  []string `json:"categories" validate:"required"`
		MalwareName string   `json:"malware_name"`
		Tags        []string `json:"tags"`
		Creator     string   `json:"creator"`
		Comment     string   `json:"comment"`
		ReportLink  []string `json:"report_link"`
	}

	RequestIOCValidate struct {
		Data []string `json:"data"`
	}

	ResponseIOCValidate struct {
		Value   string `json:"value"`
		Type    string `json:"type"`
		Verbose string `json:"verbose"`
	}

	RequestIOCPredict struct {
		Data []string `json:"data"`
	}

	ResponseIOCPredict struct {
		Label   string             `json:"label"`
		Predict defs.PredictStatus `json:"predict"`
		Verbose string             `json:"verbose"`
	}
)

func (doc *IOC) GetID() string {
	// Success
	return doc.ID
}

func (doc *IOC) SetEID(id string) {
	// Success
	doc.ID = id
}

func (doc *IOC) GenID() {
	// Success
	if doc.Type == defs.TypeSample {
		doc.ID = doc.Label
	} else {
		doc.ID = hash.SHA1(doc.Label)
	}
}

func (doc *IOCHistory) GetID() string {
	// Success
	return doc.ID
}

func (doc *IOCHistory) SetEID(id string) {
	// Success
	doc.ID = id
}

func (doc *IOCHistory) GenID() {
	// Success
	doc.ID = hash.SHA1(fmt.Sprintf("%s--%d", doc.IOC, doc.Created))
}

func (body RequestIOCSearch) Index() string {
	indexes := make([]string, 0)
	for _, kind := range body.Types {
		if idx, ok := defs.MappingIOCIndex[kind]; ok {
			indexes = append(indexes, idx)
		}
	}
	if len(indexes) == 0 {
		return fmt.Sprintf(defs.IndexIOC, "*")
	}
	// Success
	return strings.Join(indexes, ",")
}

func (body RequestIOCSearch) Query() map[string]interface{} {
	filter := make([]interface{}, 0)
	if body.Keyword != "" {
		filter = append(filter, map[string]interface{}{
			"wildcard": map[string]interface{}{
				"label": fmt.Sprintf("*%s*", regexp.QuoteMeta(body.Keyword)),
			},
		})
	}
	if len(body.Tags) > 0 {
		filter = append(filter, map[string]interface{}{
			"terms": map[string]interface{}{
				"attribute.tags": body.Tags,
			},
		})
	}
	if len(body.Categories) > 0 {
		filter = append(filter, map[string]interface{}{
			"terms": map[string]interface{}{
				"categories": body.Categories,
			},
		})
	}
	if len(body.Status) > 0 {
		filter = append(filter, map[string]interface{}{
			"terms": map[string]interface{}{
				"malicious": body.Status,
			},
		})
	}
	createdFilter := map[string]interface{}{}
	if body.Created.Gte > 0 {
		gte, _ := clock.ParseMilliTimestamp(body.Created.Gte, clock.Local)
		createdFilter["gte"] = clock.UnixMilli(gte)
	}
	if body.Created.Lte > 0 {
		lte, _ := clock.ParseMilliTimestamp(body.Created.Lte, clock.Local)
		createdFilter["lte"] = clock.UnixMilli(lte)
	}
	if len(createdFilter) > 0 {
		filter = append(filter, map[string]interface{}{"range": map[string]interface{}{"creation_date": createdFilter}})
	}
	modifiedFilter := map[string]interface{}{}
	if body.Modified.Gte > 0 {
		gte, _ := clock.ParseMilliTimestamp(body.Modified.Gte, clock.Local)
		modifiedFilter["gte"] = clock.UnixMilli(gte)
	}
	if body.Modified.Lte > 0 {
		lte, _ := clock.ParseMilliTimestamp(body.Modified.Lte, clock.Local)
		modifiedFilter["lte"] = clock.UnixMilli(lte)
	}
	if len(modifiedFilter) > 0 {
		filter = append(filter, map[string]interface{}{"range": map[string]interface{}{"updated_date": modifiedFilter}})
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

func (body RequestIOCCreate) Generate() []*IOC {
	results := make([]*IOC, 0)
	for _, data := range body.Data {
		now, _ := clock.Now(clock.Local)
		nowStr := clock.Format(now, clock.FormatRFC3339)
		ioc := &IOC{
			Label:       data.Label,
			Created:     nowStr,
			Modified:    nowStr,
			Malicious:   body.Status,
			MalwareName: body.MalwareName,
			Categories:  body.Categories,
			Ranking:     defs.DefaultIOCRank,
			Attribute: IOCAttribute{
				Tags:  body.Tags,
				Regex: body.Regex,
			},
			ReportLink: body.ReportLink,
		}
		if _, ok := defs.MappingIOCType[data.Type]; !ok {
			continue
		} else {
			ioc.Type = data.Type
			if ioc.Type == defs.TypeUnknown {
				continue
			}
			if ioc.Type != defs.TypeURL {
				ioc.Label = strings.ToLower(ioc.Label)
			}
		}
		if body.Source != "" {
			ioc.Source = []string{body.Source}
		} else {
			ioc.Source = []string{defs.DefaultIOCSource}
		}
		ioc.GenID()
		results = append(results, ioc)
	}
	// Success
	return results
}
