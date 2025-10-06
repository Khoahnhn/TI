package model

import (
	"fmt"
	"strings"
	"time"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/multilang"
)

type (
	TTIAlert struct {
		ID      string   `json:"id"`
		Eids    []string `json:"eids"`
		Title   string   `json:"title"`
		Source  string   `json:"source"`
		Created int64    `json:"created_time"`
		Assess  int      `json:"assess"`
		Message string   `json:"message"`
		Cats    []string `json:"cats"`
	}

	TTIEvent struct {
		ID           string                 `json:"id"`
		Src          string                 `json:"src"`
		Alert        string                 `json:"alert"`
		Category     string                 `json:"category"`
		Message      map[string]interface{} `json:"message"`
		Organization string                 `json:"organization"`
	}

	TTIEventBrand struct {
		Created string `json:"creation_time"`
		Domain  string `json:"domain"`
		Image   string `json:"image"`
		Ratio   int    `json:"ratio"`
		Status  string `json:"status"`
		Target  string `json:"target"`
	}

	TTIEventIntelligence struct {
		IntelID string `json:"intel_id"`
		Title   string `json:"title"`
	}

	TTIEventLeak struct {
	}

	TTIEventCompromisedSystem struct {
		Connected int64  `json:"connected"`
		Published int64  `json:"published"`
		IPAddress string `json:"ipaddress"`
		IOC       string `json:"ioc"`
		Malware   string `json:"malware"`
		Assess    int    `json:"access"`
		Severity  int    `json:"severity"`
	}

	TTIEventPortAnomaly struct {
		Created   int64    `json:"created"`
		ID        string   `json:"id"`
		IPAddress string   `json:"ipaddress"`
		Port      int      `json:"port"`
		Services  []string `json:"services"`
		Assess    int      `json:"access"`
		Severity  int      `json:"severity"`
	}

	TTIEventTargetedVulnerability struct {
		Created       int64  `json:"created"`
		Title         string `json:"title"`
		SRC           string `json:"src"`
		Vulnerability string `json:"vulnerability"`
		Summary       string `json:"summary"`
		Impact        string `json:"impact"`
		Image         string `json:"image"`
		Actionable    string `json:"actionable"`
		Assess        int    `json:"access"`
		Severity      int    `json:"severity"`
	}

	TTIConfig struct {
		Alert    TTIConfigAlert    `json:"alert" bson:"alert"`
		Severity TTIConfigSeverity `json:"severity" bson:"severity"`
	}

	TTIConfigAlert struct {
		Url      string            `json:"url" bson:"url"`
		Titles   map[string]string `json:"titles" bson:"titles"`
		TitlesEN map[string]string `json:"titles_en" bson:"titles_en"`
	}

	TTIConfigSeverity struct {
		Serious int `json:"serious" bson:"serious"`
		High    int `json:"high" bson:"high"`
		Medium  int `json:"medium" bson:"medium"`
		Low     int `json:"low" bson:"low"`
	}

	TTISupport struct {
		Object   string    `json:"object" bson:"object"`
		Created  time.Time `json:"creation_time" bson:"creation_time"`
		Updated  time.Time `json:"updated_time" bson:"updated_time"`
		Category string    `json:"category" bson:"category"`
		Status   string    `json:"status" bson:"status"`
		Clients  []string  `json:"client" bson:"client"`
	}

	/*
		Request
	*/
	RequestTTIAlertExport struct {
		Query   string     `json:"query"`
		Targets []string   `json:"targets"`
		Export  []string   `json:"export"`
		Created RangeInt64 `json:"created"`
		Lang    string     `json:"lang"`
	}

	RequestTTIAlertDelivery struct {
		Query   string     `json:"query"`
		Target  string     `json:"target"`
		Export  []string   `json:"export"`
		Created RangeInt64 `json:"created"`
		To      []string   `json:"to"`
		Lang    string     `json:"lang"`
	}
)

func (doc *TTIAlert) GetID() string {
	// Success
	return doc.ID
}

func (doc *TTIEvent) GetID() string {
	// Success
	return doc.ID
}

func (doc *TTIEvent) SetEID(id string) {
	// Success
	doc.ID = id
}

func (doc *TTIEventBrand) GetObject() string {
	object := fmt.Sprintf("- %s", doc.Domain)
	object = strings.ReplaceAll(object, "[", "")
	object = strings.ReplaceAll(object, "]", "")
	paths := strings.Split(object, ".")
	if len(paths) >= 2 {
		paths[len(paths)-1] = fmt.Sprintf("]%s", paths[len(paths)-1])
		paths[len(paths)-2] = fmt.Sprintf("%s[", paths[len(paths)-2])
	}
	// Success
	return strings.Join(paths, ".")
}

func (doc *TTIEventIntelligence) GetObject() string {
	object := fmt.Sprintf("- %s", doc.IntelID)
	// Success
	return object
}

func (doc *TTIEventLeak) GetObject() string {
	// Success
	return ""
}

func (doc *TTIEventCompromisedSystem) GetObject() string {
	object := fmt.Sprintf("- %s -> %s", doc.IPAddress, doc.IOC)
	// Success
	return object
}

func (doc *TTIEventPortAnomaly) GetObject() string {
	object := fmt.Sprintf("- %s:%d", doc.IPAddress, doc.Port)
	// Success
	return object
}

func (doc *TTIEventTargetedVulnerability) GetObject() string {
	object := fmt.Sprintf("- %s (%s)", doc.SRC, doc.Vulnerability)
	// Success
	return object
}

func (doc *TTIConfigSeverity) GetSeverity(assess int) int {
	// Success
	if assess < doc.Low {
		return 0
	} else if assess >= doc.Low && assess < doc.Medium {
		return 1
	} else if assess >= doc.Medium && assess < doc.High {
		return 2
	} else {
		return 3
	}
}

func (doc *TTISupport) GetObject() string {
	object := doc.Object
	object = strings.ReplaceAll(object, "[", "")
	object = strings.ReplaceAll(object, "]", "")
	paths := strings.Split(object, ".")
	if len(paths) >= 2 {
		paths[len(paths)-1] = fmt.Sprintf("]%s", paths[len(paths)-1])
		paths[len(paths)-2] = fmt.Sprintf("%s[", paths[len(paths)-2])
	}
	// Success
	return strings.Join(paths, ".")
}

func (doc *TTISupport) GetCompleteTime() string {
	switch doc.Status {
	case defs.StatusDone, defs.StatusReject:
		return clock.Format(doc.Updated, clock.FormatHuman)
	default:
		return defs.TitleNA
	}
}

func (doc *TTISupport) GetProcess(lang string) string {
	switch doc.Status {
	case defs.StatusPending, defs.StatusInprogress:
		return defs.TitleNA
	case defs.StatusDone, defs.StatusReject:
		delta := (float64(doc.Updated.Unix()) / 3600) - (float64(doc.Created.Unix()) / 3600)
		return fmt.Sprintf(multilang.Get(lang, multilang.KeyProcessTimeData), delta)
	}
	// Fail
	return ""
}

func (body *RequestTTIAlertExport) PrepareTTIAlertRequest() map[string]interface{} {
	filter := make([]interface{}, 0)
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
		filter = append(filter, map[string]interface{}{"range": map[string]interface{}{"created_time": createdFilter}})
	}
	// TODO: Parse Query
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

func (body *RequestTTIAlertExport) PrepareTTISupportRequest() *bson.M {
	filter := bson.M{}
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
		filter["creation_time"] = created
	}
	if len(body.Targets) > 0 {
		all := false
		for _, target := range body.Targets {
			if target == "all" {
				all = true
			}
		}
		if !all {
			filter["client"] = bson.M{"$in": body.Targets}
		}
	}
	// Success
	return &filter
}

func (body *RequestTTIAlertExport) GetSuffix(lang string) string {
	creationGte, _ := clock.ParseMilliTimestamp(body.Created.Gte, clock.Local)
	creationLte, _ := clock.ParseMilliTimestamp(body.Created.Lte, clock.Local)
	if body.Created.Gte > 0 && body.Created.Lte > 0 {
		return fmt.Sprintf(multilang.Get(lang, multilang.KeySuffixDate), clock.Format(creationGte, clock.FormatHuman), clock.Format(creationLte, clock.FormatHuman))
	} else {
		if body.Created.Gte > 0 {
			return fmt.Sprintf(multilang.Get(lang, multilang.KeySuffixDateGte), clock.Format(creationGte, clock.FormatHuman))
		}
		if body.Created.Lte > 0 {
			return fmt.Sprintf(multilang.Get(lang, multilang.KeySuffixDateLte), clock.Format(creationLte, clock.FormatHuman))
		}
	}
	// Failed
	return ""
}

func (body *RequestTTIAlertDelivery) PrepareTTIAlertRequest() map[string]interface{} {
	filter := make([]interface{}, 0)
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
		filter = append(filter, map[string]interface{}{"range": map[string]interface{}{"created_time": createdFilter}})
	}
	// TODO: Parse Query
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

func (body *RequestTTIAlertDelivery) PrepareTTISupportRequest() *bson.M {
	filter := bson.M{}
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
		filter["creation_time"] = created
	}
	if body.Target != "" {
		filter["client"] = body.Target
	}
	// Success
	return &filter
}

func (body *RequestTTIAlertDelivery) GetSuffix() string {
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
