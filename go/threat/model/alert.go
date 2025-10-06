package model

import (
	"fmt"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
)

type (
	// Request
	RequestAlertExport struct {
		AlertExport
		Lang    string   `json:"lang"`
		Feature []string `json:"feature"`
		To      []string `json:"to"`
	}

	AlertExport struct {
		Target   []string   `json:"target"`
		Severity []string   `json:"severity"`
		Status   []string   `json:"status"`
		Created  RangeInt64 `json:"created"`
	}
)

func (body *AlertExport) PrepareBrandAbuseQuery() *bson.M {
	filter := bson.M{"verify": true, "alert": true}
	created := bson.M{}
	if body.Created.Gte > 0 {
		gte, _ := clock.ParseMilliTimestamp(body.Created.Gte, clock.Local)
		created["$gte"] = gte
	}
	if body.Created.Lte > 0 {
		lte, _ := clock.ParseMilliTimestamp(body.Created.Lte, clock.Local)
		created["$lte"] = lte
	}
	if len(created) > 0 {
		filter["monitor_time"] = created
	}
	if len(body.Target) > 0 {
		all := false
		for _, target := range body.Target {
			if target == "all" {
				all = true
			}
		}
		if !all {
			filter["target"] = bson.M{"$in": body.Target}
		}
	}
	// Success
	return &filter
}

func (body *AlertExport) PrepareIntelligenceMalwareQuery() map[string]interface{} {
	filter := make([]interface{}, 0)
	filter = append(filter, map[string]interface{}{"term": map[string]interface{}{"type": defs.MappingFeatureType[defs.FeatureIntelligenceMalware]}})
	if len(body.Severity) > 0 {
		severity := make([]interface{}, 0)
		for _, s := range body.Severity {
			severity = append(severity, map[string]interface{}{"term": map[string]interface{}{"severity": defs.MappingSeverity[s]}})
		}
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": severity,
			},
		})
	}
	if len(body.Target) > 0 {
		should := make([]interface{}, 0)
		all := false
		for _, target := range body.Target {
			if target == "all" {
				all = true
			}
		}
		if !all {
			for _, target := range body.Target {
				should = append(should, map[string]interface{}{
					"term": map[string]interface{}{
						"group_list": target,
					},
				})
			}
			filter = append(filter, map[string]interface{}{
				"bool": map[string]interface{}{
					"should": should,
				},
			})
		}
	}
	createdFilter := map[string]interface{}{}
	if body.Created.Gte > 0 {
		gte, _ := clock.ParseMilliTimestamp(body.Created.Gte, clock.Local)
		createdFilter["gte"] = clock.Format(gte, clock.FormatRFC3339)
	}
	if body.Created.Lte > 0 {
		lte, _ := clock.ParseMilliTimestamp(body.Created.Lte, clock.Local)
		createdFilter["lte"] = clock.Format(lte, clock.FormatRFC3339)
	}
	if len(createdFilter) > 0 {
		filter = append(filter, map[string]interface{}{"range": map[string]interface{}{"creation_date": createdFilter}})
	}
	// Success
	if len(filter) > 0 {
		return map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filter,
			},
		}
	} else {
		return defs.ElasticsearchQueryFilterMatchAll
	}
}

func (body *AlertExport) PrepareIntelligenceVulnerabilityQuery() map[string]interface{} {
	filter := make([]interface{}, 0)
	filter = append(filter, map[string]interface{}{"term": map[string]interface{}{"type": defs.MappingFeatureType[defs.FeatureIntelligenceVulnerability]}})
	if len(body.Severity) > 0 {
		severity := make([]interface{}, 0)
		for _, s := range body.Severity {
			severity = append(severity, map[string]interface{}{"term": map[string]interface{}{"severity": defs.MappingSeverity[s]}})
		}
		filter = append(filter, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": severity,
			},
		})
	}
	if len(body.Target) > 0 {
		should := make([]interface{}, 0)
		all := false
		for _, target := range body.Target {
			if target == "all" {
				all = true
			}
		}
		if !all {
			for _, target := range body.Target {
				should = append(should, map[string]interface{}{
					"term": map[string]interface{}{
						"group_list": target,
					},
				})
			}
			filter = append(filter, map[string]interface{}{
				"bool": map[string]interface{}{
					"should": should,
				},
			})
		}
	}
	createdFilter := map[string]interface{}{}
	if body.Created.Gte > 0 {
		gte, _ := clock.ParseMilliTimestamp(body.Created.Gte, clock.Local)
		createdFilter["gte"] = clock.Format(gte, clock.FormatRFC3339)
	}
	if body.Created.Lte > 0 {
		lte, _ := clock.ParseMilliTimestamp(body.Created.Lte, clock.Local)
		createdFilter["lte"] = clock.Format(lte, clock.FormatRFC3339)
	}
	if len(createdFilter) > 0 {
		filter = append(filter, map[string]interface{}{"range": map[string]interface{}{"creation_date": createdFilter}})
	}
	// Success
	if len(filter) > 0 {
		return map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filter,
			},
		}
	} else {
		return defs.ElasticsearchQueryFilterMatchAll
	}
}

func (body *AlertExport) GetSuffix() string {
	creationGte, _ := clock.ParseMilliTimestamp(body.Created.Gte, clock.Local)
	creationLte, _ := clock.ParseMilliTimestamp(body.Created.Lte, clock.Local)
	if body.Created.Gte > 0 && body.Created.Lte > 0 {
		return fmt.Sprintf(defs.SuffixDate, clock.Format(creationGte, clock.FormatHuman), clock.Format(creationLte, clock.FormatHuman))
	} else {
		if body.Created.Gte > 0 {
			return fmt.Sprintf(defs.SuffixDateGte, clock.Format(creationGte, clock.FormatHuman))
		}
		if body.Created.Lte > 0 {
			return fmt.Sprintf(defs.SuffixDateLte, clock.Format(creationLte, clock.FormatHuman))
		}
	}
	// Failed
	return ""
}
