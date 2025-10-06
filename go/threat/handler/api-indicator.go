package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"github.com/panjf2000/ants/v2"
	es "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/kafka"
	"gitlab.viettelcyber.com/awesome-threat/library/arrayx"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
	"gitlab.viettelcyber.com/awesome-threat/library/tld"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
	"gitlab.viettelcyber.com/awesome-threat/library/virustotal"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/utils"
)

type IndicatorHandler struct {
	name      string
	logger    pencil.Logger
	elastic   elastic.GlobalRepository
	extractor tld.Service
	scanChan  chan *udm.EntityJob
	syncChan  chan *model.IOC
	config    model.Config
}

func NewIndicatorHandler(ctx context.Context, config model.Config) IndicatorInterface {
	logger, _ := pencil.New(defs.HandlerIndicator, pencil.DebugLevel, true, os.Stdout)

	tldCachePath := os.Getenv(defs.EnvTldCachePath)
	if tldCachePath == "" {
		tldCachePath = defs.DefaultTLDCacheFilePath
	}

	handler := &IndicatorHandler{
		name:      defs.HandlerIndicator,
		logger:    logger,
		elastic:   elastic.NewGlobalRepository(config.Connector.Elastic),
		extractor: tld.NewService(tldCachePath),
		config:    config,
	}

	if handler.config.Api.Timeout == 0 {
		handler.config.Api.Timeout = defs.DefaultTimeout
	}
	if handler.config.App.Core == 0 {
		handler.config.App.Core = runtime.NumCPU()
	}

	handler.scanChan = make(chan *udm.EntityJob, handler.config.App.Core*100)
	handler.syncChan = make(chan *model.IOC, handler.config.App.Core*100)
	// Scan Thread
	go handler.handleScanRequests(ctx)
	go func() {
		<-ctx.Done()
		close(handler.scanChan)
	}()
	// Sync Thread
	go handler.syncThreatFeed(ctx)
	go func() {
		<-ctx.Done()
		close(handler.syncChan)
	}()
	// Success
	return handler
}

func (h *IndicatorHandler) Config(c echo.Context) error {
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{
		"status":   defs.MappingIOCStatus,
		"type":     defs.MappingIOCType,
		"category": defs.EnumIOCCategories,
		"regex":    defs.EnumIOCRegex,
	}).Go()
}

func (h *IndicatorHandler) Search(c echo.Context) error {
	body, err := h.verifySearch(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	index := body.Index()
	query := body.Query()
	bts, _ := json.Marshal(query)
	h.logger.Infof("query: %s", string(bts))
	results := make([]*model.IOC, 0)
	if body.Size == -1 {
		results, err = h.elastic.Enrichment().IOC().FindAll(context.Background(), index, query, body.Sorts)
	} else {
		results, err = h.elastic.Enrichment().IOC().Find(context.Background(), index, query, body.Sorts, body.Offset, body.Size)
	}
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	count, err := h.elastic.Enrichment().IOC().Count(context.Background(), index, query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results, "total": count}).Go()
}

func (h *IndicatorHandler) Statistic(c echo.Context) error {
	aggs, err := h.elastic.Enrichment().IOC().AggregationCount(context.Background(), fmt.Sprintf(defs.IndexIOC, "*"), defs.ElasticsearchQueryFilterMatchAll, []string{"type", "malicious"})
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(aggs).Go()
}

func (h *IndicatorHandler) Create(c echo.Context) error {
	body, err := h.verifyCreate(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	now, _ := clock.Now(clock.Local)
	documents := body.Generate()
	results := make([]*model.IOC, 0)
	histories := make([]*model.IOCHistory, 0)
	for _, document := range documents {
		if _, err = h.elastic.Enrichment().IOC().GetByID(context.Background(), defs.MappingIOCIndex[document.Type], document.ID); err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			results = append(results, document)
			history := &model.IOCHistory{
				Created: clock.UnixMilli(now),
				IOC:     document.ID,
				Creator: body.Creator,
				Action:  defs.ActionCreateIOC,
				Comment: body.Comment,
			}
			history.GenID()
			histories = append(histories, history)
		}
	}
	if err = h.elastic.Enrichment().IOC().StoreAll(context.Background(), results); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if err = h.elastic.Enrichment().IOCHistory().StoreAll(context.Background(), histories); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	go func() {
		for _, result := range results {
			h.syncChan <- result
			h.publishUDM(result)
		}
	}()
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"duplicate": len(documents) - len(results), "success": len(results)}).Go()
}

func (h *IndicatorHandler) Edit(c echo.Context) error {
	body, err := h.verifyEdit(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	saved, err := h.elastic.Enrichment().IOC().FindByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusNotFound).Log(err).Go()
	}
	now, _ := clock.Now(clock.Local)
	changes := make([]string, 0)
	saved.Modified = clock.Format(now, clock.FormatRFC3339)
	if saved.Malicious != body.Status {
		changes = append(changes, fmt.Sprintf("Status (%s -> %s)", defs.MappingIOCStatus[saved.Malicious], defs.MappingIOCStatus[body.Status]))
		saved.Malicious = body.Status
	}
	if saved.Attribute.Regex != body.Regex {
		changes = append(changes, fmt.Sprintf("Regex (%s -> %s)", saved.Attribute.Regex, body.Regex))
		saved.Attribute.Regex = body.Regex
	}
	if !slice.String(saved.Attribute.Tags).Equal(slice.String(body.Tags)) {
		changes = append(changes, fmt.Sprintf("Tags ([%s] -> [%s])", strings.Join(saved.Attribute.Tags, ","), strings.Join(body.Tags, ",")))
		saved.Attribute.Tags = body.Tags
	}
	if !slice.String(saved.Categories).Equal(slice.String(body.Categories)) {
		changes = append(changes, fmt.Sprintf("Categories ([%s] -> [%s])", strings.Join(saved.Categories, ","), strings.Join(body.Categories, ",")))
		saved.Categories = body.Categories
	}
	if saved.MalwareName != body.MalwareName {
		changes = append(changes, fmt.Sprintf("Malware Name (%s -> %s)", saved.MalwareName, body.MalwareName))
		saved.MalwareName = body.MalwareName
	}
	saved.ReportLink = body.ReportLink

	if err = h.elastic.Enrichment().IOC().Update(context.Background(), defs.MappingIOCIndex[saved.Type], saved); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	go func() {
		h.syncChan <- saved
		h.publishUDM(saved)
	}()
	history := &model.IOCHistory{
		Created: clock.UnixMilli(now),
		IOC:     saved.ID,
		Creator: body.Creator,
		Action:  fmt.Sprintf(defs.ActionEditIOC, strings.Join(changes, ", ")),
		Comment: body.Comment,
	}
	history.GenID()
	if err = h.elastic.Enrichment().IOCHistory().Store(context.Background(), history); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(saved.ID).Go()
}

func (h *IndicatorHandler) History(c echo.Context) error {
	body, err := h.verifyIOCID(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	histories, err := h.elastic.Enrichment().IOCHistory().FindByIOCID(context.Background(), body.ID)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusOK).Body(make([]interface{}, 0)).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(histories).Go()
}

func (h *IndicatorHandler) Validate(c echo.Context) error {
	body, err := h.verifyValidate(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	results := make([]*model.ResponseIOCValidate, 0)
	for _, item := range body.Data {
		result := &model.ResponseIOCValidate{
			Value:   item,
			Type:    utils.GetType(item),
			Verbose: utils.GetVerbose(item),
		}
		if result.Type != defs.AssetTypeURL {
			result.Value = strings.ToLower(result.Value)
		}
		results = append(results, result)
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(results).Go()
}

// Predict returns a prediction result for a given list of IOC data. The prediction result is based on the Virustotal API.
// The prediction result is one of the following:
//
// - defs.PredictStatusClean: The IOC is clean.
// - defs.PredictStatusMalicious: The IOC is malicious.
// - defs.PredictStatusSuspicious: The IOC is suspicious.
// - defs.PredictStatusUnknown: The prediction failed.
// - defs.PredictStatusError: The prediction failed due to an error.
//
// The response body is a list of model.ResponseIOCPredict objects, each containing the prediction result and a verbose message.
func (h *IndicatorHandler) Predict(c echo.Context) error {
	body, err := h.verifyPredict(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	results := make([]*model.ResponseIOCPredict, len(body.Data))
	wg := &sync.WaitGroup{}
	p, _ := ants.NewPoolWithFunc(h.config.App.Core, func(body interface{}) {
		defer wg.Done()
		data := body.(*jobPredict)
		kind := utils.GetType(data.Label)
		if kind != defs.TypeSample {
			results[data.Index] = &model.ResponseIOCPredict{Label: data.Label, Predict: defs.PredictStatusUnknown, Verbose: defs.VerboseUnsupportedIndicatorType}
			return
		}
		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
		client.SetTimeout(time.Duration(clock.Minute * clock.Duration(h.config.Api.Timeout)))
		if h.config.Api.Credential.Enrichment.Enable {
			client.SetBasicAuth(h.config.Api.Credential.Enrichment.Username, h.config.Api.Credential.Enrichment.Password)
		}
		res, err := client.R().SetHeader(rest.HeaderContentType, rest.MIMEApplicationJSON).SetBody(&model.RequestVirustotalFileReport{Value: data.Label, Force: false}).Post(fmt.Sprintf(defs.UriVirustotalFileReport, h.config.Api.Route.Enrichment))
		if err != nil {
			h.logger.Errorf("client.R.Post failed, reason: %v", err)
			results[data.Index] = &model.ResponseIOCPredict{Label: data.Label, Predict: defs.PredictStatusError, Verbose: defs.VerbosePredictFailed}
			return
		}
		if res.StatusCode() != rest.StatusOK {
			h.logger.Errorf("client.R.Post return code %d", res.StatusCode())
			results[data.Index] = &model.ResponseIOCPredict{Label: data.Label, Predict: defs.PredictStatusError, Verbose: defs.VerbosePredictFailed}
			return
		}
		var result model.ResponseVirustotalFileReport
		if err = json.Unmarshal(res.Body(), &result); err != nil {
			h.logger.Errorf("json.Unmarshal failed, reason: %v", err)
			results[data.Index] = &model.ResponseIOCPredict{Label: data.Label, Predict: defs.PredictStatusError, Verbose: defs.VerbosePredictFailed}
			return
		}
		if result.Detail == nil {
			results[data.Index] = &model.ResponseIOCPredict{Label: data.Label, Predict: defs.PredictStatusError, Verbose: defs.VerbosePredictFailed}
			return
		}
		if result.Detail.Attributes == nil {
			results[data.Index] = &model.ResponseIOCPredict{Label: data.Label, Predict: defs.PredictStatusError, Verbose: defs.VerbosePredictFailed}
			return
		}
		if result.Detail.Attributes.LastAnalysisResults == nil {
			results[data.Index] = &model.ResponseIOCPredict{Label: data.Label, Predict: defs.PredictStatusError, Verbose: defs.VerbosePredictFailed}
			return
		}
		totalMalicious := 0
		totalSuspicious := 0
		totalTypeUnsupported := 0
		totalUndetected := 0
		totalHarmless := 0
		totalFailure := 0
		totalTimeout := 0
		totalConfirmedTimeout := 0
		totalTrustedAVDetected := make([]string, 0)
		for av, pre := range result.Detail.Attributes.LastAnalysisResults {
			switch pre.Category {
			case virustotal.CategoryMalicious:
				totalMalicious++
				if arrayx.Contain(h.config.App.Predict.TrustedAVs, av) {
					totalTrustedAVDetected = append(totalTrustedAVDetected, av)
				}
			case virustotal.CategorySuspicious:
				totalSuspicious++
			case virustotal.CategoryTypeUnsupported:
				totalTypeUnsupported++
			case virustotal.CategoryUndetected:
				totalUndetected++
			case virustotal.CategoryHarmless:
				totalHarmless++
			case virustotal.CategoryFailure:
				totalFailure++
			case virustotal.CategoryTimeout:
				totalTimeout++
			case virustotal.CategoryConfirmedTimeout:
				totalConfirmedTimeout++
			}
		}
		// Malicious with Trusted AV
		if len(totalTrustedAVDetected) > 0 {
			verbose := fmt.Sprintf(defs.VerbosePredictMaliciousVirustotalWithTrustAV,
				strings.Join(totalTrustedAVDetected, ","),
				totalMalicious,
				totalSuspicious,
				totalTypeUnsupported,
				totalUndetected,
				totalHarmless,
				totalFailure,
				totalTimeout,
				totalConfirmedTimeout,
			)
			results[data.Index] = &model.ResponseIOCPredict{Label: data.Label, Predict: defs.PredictStatusMalicious, Verbose: verbose}
			return
		}
		// Malicious with Threshold
		if totalMalicious > h.config.App.Predict.ThresholdAV {
			verbose := fmt.Sprintf(defs.VerbosePredictMaliciousVirustotal,
				totalMalicious,
				totalSuspicious,
				totalTypeUnsupported,
				totalUndetected,
				totalHarmless,
				totalFailure,
				totalTimeout,
				totalConfirmedTimeout,
			)
			results[data.Index] = &model.ResponseIOCPredict{Label: data.Label, Predict: defs.PredictStatusMalicious, Verbose: verbose}
			return
		}
		// Clean
		if totalMalicious == 0 {
			verbose := fmt.Sprintf(defs.VerbosePredictMaliciousVirustotal,
				totalMalicious,
				totalSuspicious,
				totalTypeUnsupported,
				totalUndetected,
				totalHarmless,
				totalFailure,
				totalTimeout,
				totalConfirmedTimeout,
			)
			results[data.Index] = &model.ResponseIOCPredict{Label: data.Label, Predict: defs.PredictStatusClean, Verbose: verbose}
			return
		}
		// Suspicious
		verbose := fmt.Sprintf(defs.VerbosePredictMaliciousVirustotal,
			totalMalicious,
			totalSuspicious,
			totalTypeUnsupported,
			totalUndetected,
			totalHarmless,
			totalFailure,
			totalTimeout,
			totalConfirmedTimeout,
		)
		results[data.Index] = &model.ResponseIOCPredict{Label: data.Label, Predict: defs.PredictStatusSuspicious, Verbose: verbose}
		return
	})
	defer p.Release()
	for idx, item := range body.Data {
		wg.Add(1)
		if err := p.Invoke(&jobPredict{Index: idx, Label: item}); err != nil {
			h.logger.Errorf("p.Invoke failed, reason: %v", err)
			continue
		}
	}
	wg.Wait()
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(results).Go()
}

func (h *IndicatorHandler) Tags(c echo.Context) error {
	result, err := h.elastic.Enrichment().IOC().AggregationTopHits(context.Background(), fmt.Sprintf(defs.IndexIOC, "*"), defs.ElasticsearchQueryFilterMatchAll, "attribute.tags", 20000)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(result).Go()
}

func (h *IndicatorHandler) verifySearch(c echo.Context) (body model.RequestIOCSearch, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if len(body.Tags) > 0 {
		tags := make([]string, 0)
		for _, tag := range body.Tags {
			tags = append(tags, strings.ToLower(strings.TrimSpace(tag)))
		}
		body.Tags = tags
	}
	if len(body.Categories) > 0 {
		categories := make([]string, 0)
		for _, category := range body.Categories {
			category = strings.ToLower(strings.TrimSpace(category))
			if category == "all" {
				categories = make([]string, 0)
				break
			} else {
				categories = append(categories, category)
			}
		}
		body.Categories = categories
	}
	if len(body.Types) > 0 {
		types := make([]string, 0)
		for _, kind := range body.Types {
			kind = strings.ToLower(strings.TrimSpace(kind))
			if _, ok := defs.MappingIOCType[kind]; !ok {
				return body, errors.New("invalid value for parameter <types>")
			}
			types = append(types, kind)
		}
		body.Types = types
	}
	if len(body.Status) > 0 {
		status := make([]int, 0)
		for _, s := range body.Status {
			if _, ok := defs.MappingIOCStatus[s]; !ok {
				return body, errors.New("invalid value for parameter <status>")
			}
			status = append(status, s)
		}
		body.Status = status
	}
	if len(body.Sorts) == 0 {
		body.Sorts = []string{defs.DefaultIOCSort}
	}
	if body.Size == 0 {
		body.Size = 20
	}
	// Success
	return body, nil
}

func (h *IndicatorHandler) verifyCreate(c echo.Context) (body model.RequestIOCCreate, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if len(body.Data) == 0 {
		return body, errors.New("invalid value for parameter <regex>")
	}
	// Validate status
	if _, ok := defs.MappingIOCStatus[body.Status]; !ok {
		return body, errors.New("invalid value for parameter <status>")
	}

	details := make([]model.IOCDetail, 0)
	for _, data := range body.Data {
		data.Label = strings.TrimSpace(data.Label)
		if _, ok := defs.MappingIOCType[data.Type]; !ok {
			return body, errors.New("invalid value for parameter <data[].type>")
		}
		details = append(details, data)
	}
	reReportLink := regexp.MustCompile(defs.RegexReportLink)
	if len(body.ReportLink) != 0 {
		for _, reportLink := range body.ReportLink {
			if !reReportLink.MatchString(reportLink) {
				return body, errors.New("invalid format Report Link")
			}
		}
	}

	body.Data = details
	if body.Source != "" {
		body.Source = strings.TrimSpace(body.Source)
	}
	body.Regex = strings.ToLower(strings.TrimSpace(body.Regex))
	if body.Regex == "" {
		body.Regex = "exactly"
	}
	if !slice.String(defs.EnumIOCRegex).Contains(body.Regex) {
		return body, errors.New("invalid value for parameter <regex>")
	}
	if len(body.Categories) > 0 {
		categories := make([]string, 0)
		for _, category := range body.Categories {
			categories = append(categories, strings.TrimSpace(category))
		}
		body.Categories = categories
	} else {
		return body, errors.New("invalid value for parameter <categories>")
	}
	body.MalwareName = strings.TrimSpace(body.MalwareName)
	if len(body.Tags) > 0 {
		tags := make([]string, 0)
		for _, tag := range body.Tags {
			tags = append(tags, strings.TrimSpace(tag))
		}
		body.Tags = tags
	} else {
		body.Tags = []string{}
	}
	if body.Creator == "" {
		body.Creator = defs.DefaultUser
	}
	body.Comment = strings.TrimSpace(body.Comment)
	// Success
	return body, nil
}

func (h *IndicatorHandler) verifyEdit(c echo.Context) (body model.RequestIOCEdit, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if _, ok := defs.MappingIOCStatus[body.Status]; !ok {
		return body, errors.New("invalid value for parameter <status>")
	}
	body.Regex = strings.ToLower(strings.TrimSpace(body.Regex))
	if !slice.String(defs.EnumIOCRegex).Contains(body.Regex) {
		return body, errors.New("invalid value for parameter <regex>")
	}
	reReportLink := regexp.MustCompile(defs.RegexReportLink)
	if len(body.ReportLink) != 0 {
		for _, reportLink := range body.ReportLink {
			if !reReportLink.MatchString(reportLink) {
				return body, errors.New("invalid format Report Link")
			}
		}
	}
	if len(body.Categories) > 0 {
		categories := make([]string, 0)
		for _, category := range body.Categories {
			categories = append(categories, strings.TrimSpace(category))
		}
		body.Categories = categories
	} else {
		return body, errors.New("invalid value for parameter <categories>")
	}
	body.MalwareName = strings.TrimSpace(body.MalwareName)
	if len(body.Tags) > 0 {
		tags := make([]string, 0)
		for _, tag := range body.Tags {
			tags = append(tags, strings.TrimSpace(tag))
		}
		body.Tags = tags
	} else {
		body.Tags = []string{}
	}
	if body.Creator == "" {
		body.Creator = defs.DefaultUser
	}
	body.Comment = strings.TrimSpace(body.Comment)
	// Success
	return body, nil
}

func (h *IndicatorHandler) verifyIOCID(c echo.Context) (body model.RequestIOCID, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.ID = strings.ToLower(strings.TrimSpace(body.ID))
	// Success
	return body, nil
}

func (h *IndicatorHandler) verifyValidate(c echo.Context) (body model.RequestIOCValidate, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if len(body.Data) == 0 {
		return body, errors.New("invalid value for parameter <data>")
	}
	data := make([]string, 0)
	for _, item := range body.Data {
		data = append(data, strings.TrimSpace(item))
	}
	body.Data = data
	// Success
	return body, nil
}

// verifyPredict validates and processes the RequestIOCPredict object from the given context.
// It ensures that the Data field is not empty and trims whitespace from each data item.
// Returns an error if validation fails or if the Data field is empty.
func (h *IndicatorHandler) verifyPredict(c echo.Context) (body model.RequestIOCPredict, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if len(body.Data) == 0 {
		return body, errors.New("invalid value for parameter <data>")
	}
	data := make([]string, 0)
	for _, item := range body.Data {
		data = append(data, strings.TrimSpace(item))
	}
	body.Data = data
	// Success
	return body, nil
}

func (h *IndicatorHandler) handleScanRequests(ctx context.Context) {
	producerEvaluate, err := kafka.NewProducer(ctx, h.config.Connector.Kafka.Producers.Evaluate)
	if err != nil {
		h.logger.Errorf("failed to initialize evaluate producer: %v", err)
	}
	producerEnrichment, err := kafka.NewProducer(ctx, h.config.Connector.Kafka.Producers.Enrichment)
	if err != nil {
		h.logger.Errorf("failed to initialize enrichment producer: %v", err)
	}
	for msg := range h.scanChan {
		bts, err := json.Marshal(msg)
		if err != nil {
			h.logger.Errorf("json.Marshal failed, reason: %v", err)
			continue
		}
		if msg.CollectedEntityType == udm.EntityTypeSecurityResult {
			if err := producerEvaluate.Produce(h.config.Connector.Kafka.Topics.UDMEvaluateTopic, "", bts); err != nil {
				h.logger.Errorf("producerEvaluate.Produce failed, reason: %v", err)
			}
		} else {
			if err := producerEnrichment.Produce(h.config.Connector.Kafka.Topics.UDMEnrichmentTopic, "", bts); err != nil {
				h.logger.Errorf("producerEnrichment.Produce failed, reason: %v", err)
			}
		}
	}
}

func (h *IndicatorHandler) syncThreatFeed(ctx context.Context) {
	producer, err := kafka.NewProducer(ctx, h.config.Connector.Kafka.Producers.ThreatFeed)
	if err != nil {
		h.logger.Errorf("kafka.NewProducer failed, reason: %v", err)
		panic(any(err))
	}
	for msg := range h.syncChan {
		bts, err := json.Marshal(msg)
		if err != nil {
			h.logger.Errorf("json.Marshal failed, reason: %v", err)
			continue
		}
		if err = producer.Produce(h.config.Connector.Kafka.Topics.TAXIISyncTopic, "", bts); err != nil {
			h.logger.Errorf("producer.Produce failed, reason: %v", err)
		}
	}
}

func (h *IndicatorHandler) publishUDM(doc *model.IOC) {
	udmType, ok := defs.MappingIOCTypeUDM[doc.Type]
	if !ok {
		return
	}
	udmID := hash.SHA1(fmt.Sprintf("%s--%s", doc.Label, udmType))
	udmEntity, err := h.elastic.Enrichment().UDM().Get(context.Background(), udmID, udmType)
	if err != nil && err.Error() != es.NotFoundError {
		h.logger.Errorf("failed to get udm object for ioc %s", doc.Label)
		return
	}
	if udmEntity == nil {
		udmEntity = udm.NewEntity(doc.Label, udmType)
		switch udmType {
		case udm.EntityTypeDomain:
			extracted := h.extractor.Extract("http://" + doc.Label)
			udmEntity.Noun.Domain = &udm.Domain{
				Name: doc.Label,
				TLD:  extracted.TLD,
				Root: extracted.Root,
				Sub:  extracted.Sub,
			}
		case udm.EntityTypeIPAddress:
			ipType := udm.IPTypeIPv4
			if utils.IsIPv6(doc.Label) {
				ipType = udm.IPTypeIPv6
			}
			udmEntity.Noun.IP = &udm.IP{
				IP:       doc.Label,
				IPNumber: utils.IPToInt(doc.Label, ipType),
				Type:     ipType,
			}
		}
		if err := h.elastic.Enrichment().UDM().InsertOne(context.Background(), udmEntity, udmEntity.GetType()); err != nil {
			h.logger.Errorf("failed to insert udm object for ioc %s", doc.Label)
			return
		}
		// Get enrichment info if udm object does not exist
		h.scanChan <- &udm.EntityJob{
			Entity:              *udmEntity,
			CollectedEntityType: "",
		}
	}
	// Renew security result
	h.scanChan <- &udm.EntityJob{
		Entity:              *udmEntity,
		CollectedEntityType: udm.EntityTypeSecurityResult,
	}
}

type jobPredict struct {
	Label string
	Index int
}
