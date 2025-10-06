package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/k3a/html2text"
	"github.com/labstack/echo/v4"
	"github.com/panjf2000/ants/v2"
	es "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/rabbit"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/redis"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/core/cpe"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/sync/errgroup"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type CVEHandler struct {
	name         string
	logger       pencil.Logger
	elastic      elastic.GlobalRepository
	mongo        mongo.GlobalRepository
	queue        rabbit.Service
	cache        redis.Service
	assets       map[string][]*cpe.Item
	poolLanguage *ants.PoolWithFunc
	mutex        *sync.Mutex
	config       model.Config
	isTest       bool
}

type CveScoreCache struct {
	ID    string   `json:"id"`
	Score *float64 `json:"score"`
}

func NewCVEHandler(config model.Config, isTest bool) CVEHandlerInterface {
	logger, _ := pencil.New(defs.HandlerCve, pencil.DebugLevel, true, os.Stdout)
	handler := &CVEHandler{
		name:    defs.HandlerCve,
		logger:  logger,
		elastic: elastic.NewGlobalRepository(config.Connector.Elastic),
		mongo:   mongo.NewGlobalRepository(config.Connector.Mongo),
		queue:   rabbit.NewService(context.Background(), config.Connector.Rabbit.Crawler, nil),
		cache:   redis.NewService(config.Connector.Redis.General, nil),
		assets:  map[string][]*cpe.Item{},
		mutex:   &sync.Mutex{},
		config:  config,
		isTest:  isTest,
	}
	handler.poolLanguage = handler.newPoolMultilang()
	handler.crawlAsset(context.Background())
	if handler.config.Api.Timeout == 0 {
		handler.config.Api.Timeout = defs.DefaultTimeout
	}
	if handler.config.App.Core == 0 {
		handler.config.App.Core = runtime.NumCPU()
	}
	if handler.config.App.MaxSizeExport == 0 {
		handler.config.App.MaxSizeExport = defs.DefaultMaxSizeExport
	}
	// Success
	return handler
}

func (h *CVEHandler) Config(c echo.Context) error {
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{
		"severity":       defs.MappingCveSeverity,
		"severity_range": defs.MappingCveSeverityRange,
		"status":         defs.MappingCveStatus,
		"checklist": map[string]interface{}{
			defs.LangEN: defs.MappingCveChecklistEN,
			defs.LangVI: defs.MappingCveChecklistVI,
		},
		"product_type": defs.MappingProductType,
		"cvss":         defs.MappingCvss,
		"language":     defs.MappingLanguageStatistic,
	}).Go()
}

func (h *CVEHandler) Identify(c echo.Context) error {
	editor := c.Get("user_name").(string)
	c.SetCookie(&http.Cookie{
		Name:   "username",
		Value:  editor,
		Domain: c.Request().Host,
	})
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(editor).Go()
}

func (h *CVEHandler) Search(c echo.Context) error {
	body, err := h.verifySearch(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}

	if body.Time.Approved.Gte > 0 || body.Time.Approved.Lte > 0 {
		if len(body.Status) > 1 || (len(body.Status) == 1 && body.Status[0] != 2) {
			return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
		}
	}
	query := body.PrepareQuery()
	results, err := h.elastic.Enrichment().CVE().Find(context.Background(), query, body.Sort, body.Offset, body.Size)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	response := make([]*model.CVEVerbose, 0)
	sortSeverities := []string{}
	if slice.String(body.Severity.Global.Version).Contains(defs.VersionCvssV4) {
		sortSeverities = append(sortSeverities, defs.VersionCvssV4)
	}
	if slice.String(body.Severity.Global.Version).Contains(defs.VersionCvssV3) {
		sortSeverities = append(sortSeverities, defs.VersionCvssV3)
	}
	if slice.String(body.Severity.Global.Version).Contains(defs.VersionCvssV2) {
		sortSeverities = append(sortSeverities, defs.VersionCvssV2)
	}
	for _, result := range results {
		if len(sortSeverities) == 0 {
			result.Score.Global = result.GetLatestCVSSMetric()
		}
		for _, version := range sortSeverities {
			if version == defs.VersionCvssV4 && result.Score.CVSS4.Version != "" {
				if len(body.Severity.Global.SeverityVersion4) > 0 {
					if slice.Int(body.Severity.Global.SeverityVersion4).Contains(result.Score.CVSS4.Severity) {
						result.Score.Global = result.Score.CVSS4
						break
					}
				}
			}
			if version == defs.VersionCvssV3 && result.Score.CVSS3.Version != "" {
				if len(body.Severity.Global.SeverityVersion3) > 0 {
					if slice.Int(body.Severity.Global.SeverityVersion3).Contains(result.Score.CVSS3.Severity) {
						result.Score.Global = result.Score.CVSS3
						break
					}
				}
			}
			if version == defs.VersionCvssV2 && result.Score.CVSS2.Version != "" {
				if len(body.Severity.Global.SeverityVersion2) > 0 {
					if slice.Int(body.Severity.Global.SeverityVersion2).Contains(result.Score.CVSS2.Severity) {
						result.Score.Global = result.Score.CVSS2
						break
					}
				}
			}
		}
		// change the global score for displaying
		gVer, isFilter := getGreatestVersionFilter(body.Severity.Global.Version)
		if isFilter {
			switch gVer {
			case defs.VersionCvssV4:
				result.Score.Global = result.Score.CVSS4
			case defs.VersionCvssV3:
				result.Score.Global = result.Score.CVSS3
			case defs.VersionCvssV2:
				result.Score.Global = result.Score.CVSS2
			}
		}
		if result.CPEDetails == nil {
			result.CPEDetails = make([]model.CPEMatchDetail, 0)
		}
		if result.CPENodes == nil {
			result.CPENodes = make([]model.CVENode, 0)
		}
		response = append(response, &model.CVEVerbose{
			CVE: *result,
		})
	}
	wg := &sync.WaitGroup{}
	for idx, _ := range response {
		job := &model.CVEJobLanguage{
			WG:      wg,
			Index:   idx,
			Results: response,
		}
		wg.Add(1)
		if err = h.poolLanguage.Invoke(job); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	wg.Wait()
	count, err := h.elastic.Enrichment().CVE().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": response, "total": count}).Go()
}

func (h *CVEHandler) ValidateCVE(c echo.Context) error {
	body, err := h.verifySearch(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.PrepareQuery()
	results, err := h.elastic.Enrichment().CVE().Find(context.Background(), query, body.Sort, body.Offset, body.Size)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	if len(results) > 0 {
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results}).Go()
	}
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": nil}).Go()
}

func (h *CVEHandler) LifecycleCVE(c echo.Context) error {
	body, err := h.verifyLifeCycleCVE(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	// input: 1 report code và nhiều cve code
	query := body.PrepareQuery()
	cves, err := h.elastic.Enrichment().CVE().Find(context.Background(), query, nil, 0, 0)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	var cvesCode []string
	for _, cve := range cves {
		cvesCode = append(cvesCode, cve.Name)
	}
	cvesLifeCycle, err := h.elastic.Enrichment().CVELifeCycleV2().FindBulk(context.Background(), cvesCode)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	processedMap := make(map[string]bool)
	if len(cvesLifeCycle) != 0 { // trường hợp đã tìm thấy các bản ghi ứng với CVE đã có lifecycle là event detection trước đây thì update thêm
		for _, cveLifeCycle := range cvesLifeCycle {
			if cveLifeCycle.Event == model.CVE_EVENT_DETECTION {
				// Trường hợp người dùng truyền lên 1 mảng CVE Code dưới CVE Code đã tồn tại trong Lifecycle và References tương ứng của nó chưa có Report Code truyền lên thì append vào
				if slices.Contains(body.CVECode, cveLifeCycle.CVECode) && !slices.Contains(cveLifeCycle.References, body.ReportCode) {
					cveLifeCycle.References = append(cveLifeCycle.References, body.ReportCode)
				}
				err := h.elastic.Enrichment().CVELifeCycleV2().Update(context.Background(), cveLifeCycle)
				if err != nil {
					return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
				}
				processedMap[cveLifeCycle.CVECode] = true // đánh dấu là đã xử lí
			}
		}
	}
	// nếu không tìm thấy bản ghi vào thì tạo mới các bản ghi cve life cycle
	// hoặc 1 list ban đầu đã xử lí 1 phần thì xử lí add thêm phần còn lại
	var docs []*model.CVELifeCycleV2
	var cveListAfter []*model.CVE
	for _, cve := range cves {
		if !processedMap[cve.Name] {
			cveListAfter = append(cveListAfter, cve)
		}
	}
	for _, cve := range cveListAfter {
		doc := &model.CVELifeCycleV2{
			CVEId:      cve.ID,
			CVECode:    cve.Name,
			Created:    body.DetectionTime,
			Event:      model.CVE_EVENT_DETECTION,
			References: []string{body.ReportCode},
			Source:     nil,
		}
		doc.GenID()
		docs = append(docs, doc)
	}
	if err := h.elastic.Enrichment().CVELifeCycleV2().StoreBulk(context.Background(), docs); err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"message": true}).Go()
}

func getGreatestVersionFilter(
	versions []string,
) (version string, useFilter bool) {
	if slices.Contains(versions, defs.VersionCvssV4) {
		return defs.VersionCvssV4, true
	} else if slices.Contains(versions, defs.VersionCvssV3) {
		return defs.VersionCvssV3, true
	} else if slices.Contains(versions, defs.VersionCvssV2) {
		return defs.VersionCvssV2, true
	}
	return "", false
}

func trimspaceReq(req model.RequestCVESearch) model.RequestCVESearch {
	versions := make([]string, 0)
	for _, it := range req.Severity.Global.Version {
		versions = append(versions, strings.TrimSpace(it))
	}
	return model.RequestCVESearch{
		Keyword: strings.TrimSpace(req.Keyword),
		Checker: strings.TrimSpace(req.Checker),
		Severity: model.RequestCVESeverity{
			VTI: model.RequestCVESeverityVerbose{
				Version: strings.TrimSpace(req.Severity.VTI.Version),
				Value:   req.Severity.VTI.Value,
			},
			Global: model.RequestCVESeverityVerboseV2{
				Version:          versions,
				SeverityVersion2: req.Severity.Global.SeverityVersion2,
				SeverityVersion3: req.Severity.Global.SeverityVersion3,
			},
		},
		Status:    req.Status,
		Languages: req.Languages,
		Time:      req.Time,
		Sort:      req.Sort,
		Size:      req.Size,
		Offset:    req.Offset,
	}
}

func (h *CVEHandler) ExportListCve(c echo.Context) error {
	body, err := h.verifyExport(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}

	body.Ids = validateListID(body.Ids)
	cveResp := make([]*model.CVE, 0)
	if len(body.Ids) > 0 {
		var (
			wg       sync.WaitGroup
			wg1      sync.WaitGroup
			poolSize int = h.config.App.Core
		)
		type results struct {
			err   error
			value *model.CVE
		}

		result := make(chan results, 10)
		var err1 error
		wg1.Add(1)
		go func() {
			defer wg1.Done()
			for value := range result {
				if value.err != nil {
					if err.Error() != es.NotFoundError {
						err1 = value.err
					}
				}
				if value.value != nil {
					cveResp = append(cveResp, value.value)
				}
			}
		}()

		pool, _ := ants.NewPoolWithFunc(poolSize, func(i interface{}) {
			defer wg.Done()
			document, _ := h.elastic.Enrichment().CVE().GetByID(context.Background(), i.(string))

			rs := results{
				err:   err,
				value: document,
			}
			result <- rs
		})
		defer pool.Release()
		for _, id := range body.Ids {
			wg.Add(1)
			if err := pool.Invoke(id); err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}

		wg.Wait()
		close(result)
		wg1.Wait()
		if err1 != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}

	} else {
		body.Req = trimspaceReq(body.Req)
		if body.Req.Time.Approved.Gte > 0 || body.Req.Time.Approved.Lte > 0 {
			if len(body.Req.Status) > 1 || (len(body.Req.Status) == 1 && body.Req.Status[0] != 2) {
				return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
			}
		}
		query := body.Req.PrepareQuery()
		sortSeverities := []string{}
		if slice.String(body.Req.Severity.Global.Version).Contains(defs.VersionCvssV4) {
			sortSeverities = append(sortSeverities, defs.VersionCvssV4)
		}
		if slice.String(body.Req.Severity.Global.Version).Contains(defs.VersionCvssV3) {
			sortSeverities = append(sortSeverities, defs.VersionCvssV3)
		}
		if slice.String(body.Req.Severity.Global.Version).Contains(defs.VersionCvssV2) {
			sortSeverities = append(sortSeverities, defs.VersionCvssV2)
		}
		cveResp, err = h.elastic.Enrichment().CVE().Find(context.Background(), query, body.Req.Sort, body.Req.Offset, body.Req.Size)
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}
		// change the global score for displaying
		for _, cve := range cveResp {
			if len(sortSeverities) == 0 {
				cve.Score.Global = cve.GetLatestCVSSMetric()
			}
			for _, version := range sortSeverities {
				if version == defs.VersionCvssV4 && cve.Score.CVSS4.Version != "" {
					if len(body.Req.Severity.Global.SeverityVersion4) > 0 {
						if slice.Int(body.Req.Severity.Global.SeverityVersion4).Contains(cve.Score.CVSS4.Severity) {
							cve.Score.Global = cve.Score.CVSS4
							break
						}
					}
				}
				if version == defs.VersionCvssV3 && cve.Score.CVSS3.Version != "" {
					if len(body.Req.Severity.Global.SeverityVersion3) > 0 {
						if slice.Int(body.Req.Severity.Global.SeverityVersion3).Contains(cve.Score.CVSS3.Severity) {
							cve.Score.Global = cve.Score.CVSS3
							break
						}
					}
				}
				if version == defs.VersionCvssV2 && cve.Score.CVSS2.Version != "" {
					if len(body.Req.Severity.Global.SeverityVersion2) > 0 {
						if slice.Int(body.Req.Severity.Global.SeverityVersion2).Contains(cve.Score.CVSS2.Severity) {
							cve.Score.Global = cve.Score.CVSS2
							break
						}
					}
				}
			}
		}
	}

	if len(cveResp) == 0 {
		return c.JSON(http.StatusNotFound, model.ResponseNodata{
			Success: false,
			Message: "No data",
			Detail:  nil,
		})
	}
	for _, cve := range cveResp {
		if cve.Score.Global.Score == 0 && cve.Score.Global.Version == "" {
			cve.Score.Global.Severity = int(defs.NoneSeverity)
		}
	}

	exportExcel := getExportExcelData(cveResp, body.Req, defs.LangEN)
	path := ""
	if h.isTest {
		path = ".."
	}
	err = h.ExportListExcelCVE(c, exportExcel, defs.LangEN, h.isTest, path)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	return nil
}

func validateListID(ids []string) []string {
	result := make([]string, 0)
	if len(ids) == 0 {
		return result
	}
	for _, v := range ids {
		if len(strings.TrimSpace(v)) != 0 {
			result = append(result, strings.TrimSpace(v))
		}
	}
	return result
}

func (h *CVEHandler) Statistic(c echo.Context) error {
	body, err := h.verifyStatistic(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	filterAll := make([]interface{}, 0)
	filterChecker := make([]interface{}, 0)
	filterInternalFlag := make([]interface{}, 0)
	if body.Checker != "" {
		filterAll = append(filterAll, map[string]interface{}{
			"term": map[string]interface{}{
				"checker": body.Checker,
			},
		})
		filterChecker = append(filterChecker, map[string]interface{}{
			"term": map[string]interface{}{
				"checker": body.Checker,
			},
		})
	}
	if len(body.InternalFlags) > 0 {
		filterAll = append(filterAll, map[string]interface{}{
			"terms": map[string]interface{}{
				"internal_flag": body.InternalFlags,
			},
		})
		filterInternalFlag = append(filterInternalFlag, map[string]interface{}{
			"terms": map[string]interface{}{
				"internal_flag": body.InternalFlags,
			},
		})
	}
	filterWithoutChecker := filterInternalFlag
	filterWithoutInternalFlag := filterChecker
	queryAll := defs.ElasticsearchQueryFilterMatchAll
	if len(filterAll) > 0 {
		queryAll = map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filterAll,
			},
		}
	}
	queryChecker := defs.ElasticsearchQueryFilterMatchAll
	if len(filterWithoutInternalFlag) > 0 {
		queryChecker = map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filterWithoutInternalFlag,
			},
		}
	}
	queryInternalFlag := defs.ElasticsearchQueryFilterMatchAll
	if len(filterWithoutChecker) > 0 {
		queryInternalFlag = map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filterWithoutChecker,
			},
		}
	}
	severity := map[string]interface{}{}
	filterV2 := []interface{}{
		map[string]interface{}{
			"term": map[string]interface{}{
				"score.cvss_v2.version": "2.0",
			},
		},
	}
	if len(filterAll) > 0 {
		filterV2 = append(filterV2, filterAll...)
	}
	// V2
	queryV2 := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": filterV2,
		},
	}
	v2, err := h.elastic.Enrichment().CVE().AggregationCount(context.Background(), queryV2, []string{"score.cvss_v2.severity"})
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	sort.Sort(model.Float64Aggregations(v2["score.cvss_v2.severity"]))
	severity["v2"] = v2["score.cvss_v2.severity"]
	// V3
	queryV3 := map[string]interface{}{
		"bool": map[string]interface{}{
			"should": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"score.cvss_v3.version": "3.0",
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"score.cvss_v3.version": "3.1",
					},
				},
			},
		},
	}
	if len(filterAll) > 0 {
		queryV3["bool"].(map[string]interface{})["filter"] = filterAll
	}
	v3, err := h.elastic.Enrichment().CVE().AggregationCount(context.Background(), queryV3, []string{"score.cvss_v3.severity"})
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	sort.Sort(model.Float64Aggregations(v3["score.cvss_v3.severity"]))
	severity["v3"] = v3["score.cvss_v3.severity"]
	// V4
	queryV4 := map[string]interface{}{
		"bool": map[string]interface{}{
			"should": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"score.cvss_v4.version": "4.0",
					},
				},
			},
		},
	}
	if len(filterAll) > 0 {
		queryV4["bool"].(map[string]interface{})["filter"] = filterAll
	}
	v4, err := h.elastic.Enrichment().CVE().AggregationCount(context.Background(), queryV4, []string{"score.cvss_v4.severity"})
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	sort.Sort(model.Float64Aggregations(v4["score.cvss_v4.severity"]))
	severity["v4"] = v4["score.cvss_v4.severity"]

	// CNA
	queryCNA := map[string]interface{}{
		"bool": map[string]interface{}{
			"must_not": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"score.cna.version": "",
					},
				},
			},
		},
	}
	if len(filterAll) > 0 {
		queryCNA["bool"].(map[string]interface{})["filter"] = filterAll
	}
	cna, err := h.elastic.Enrichment().CVE().AggregationCount(context.Background(), queryCNA, []string{"score.cna.severity"})
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	sort.Sort(model.Float64Aggregations(cna["score.cna.severity"]))
	severity["cna"] = cna["score.cna.severity"]
	// Common
	fields := []string{
		"status",
		"checker",
		"score.vti.severity",
		"score.global.version",
		"score.global.severity",
		"languages",
		"source",
	}
	results := map[string]interface{}{}
	common, err := h.elastic.Enrichment().CVE().AggregationCount(context.Background(), queryAll, fields)
	if err != nil {
		h.logger.Errorf("failed to get common aggregation count. err: %v", err)
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	sort.Sort(model.Float64Aggregations(common["status"]))
	results["status"] = common["status"]
	// Checker
	checkerField := []string{"checker"}
	checkerAgg, err := h.elastic.Enrichment().CVE().AggregationCount(context.Background(), queryChecker, checkerField)
	if err != nil {
		h.logger.Errorf("failed to get checker aggregation count. err: %v", err)
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	checkers := make([]es.ResultAggregationCount, 0)
	for _, checker := range checkerAgg["checker"] {
		if checker.Value != "Unknown" {
			checkers = append(checkers, checker)
		}
	}
	results["checker"] = checkers
	// internal flag
	fieldsWithSize := map[string]int{"internal_flag": 10000}
	internalFlagResult, err := h.elastic.Enrichment().CVE().AggregationCountWithSize(
		context.Background(),
		queryInternalFlag,
		fieldsWithSize,
	)
	if err != nil {
		h.logger.Errorf("failed to get internal_flag aggregation count. err: %v", err)
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if internalFlagData, exists := internalFlagResult["internal_flag"]; exists {
		filteredFlags := make([]es.ResultAggregationCount, 0)
		for _, flag := range internalFlagData {
			if flag.Value != "" && flag.Value != nil {
				filteredFlags = append(filteredFlags, flag)
			}
		}
		results["internal_flag"] = filteredFlags
	}
	var totalUnknown int64 = 0
	var totalV2 int64 = 0
	var totalV3 int64 = 0
	var totalV4 int64 = 0
	var totalCNA int64 = 0
	for _, count := range v2["score.cvss_v2.severity"] {
		totalV2 += count.Count
	}
	for _, count := range v3["score.cvss_v3.severity"] {
		totalV3 += count.Count
	}
	for _, count := range v4["score.cvss_v4.severity"] {
		totalV4 += count.Count
	}
	for _, count := range cna["score.cna.severity"] {
		totalCNA += count.Count
	}
	cvss := common["score.global.version"]
	for _, item := range cvss {
		switch item.Value {
		case defs.VersionCvssV20:
			continue
		case defs.VersionCvssV30, defs.VersionCvssV31:
			continue
		case defs.VersionCvssV40:
			continue
		default:
			totalUnknown += item.Count
		}
	}
	results["cvss"] = []es.ResultAggregationCount{
		{
			Value: "4.*",
			Count: totalV4,
		},
		{
			Value: "3.*",
			Count: totalV3,
		},
		{
			Value: "2.*",
			Count: totalV2,
		},
		{
			Value: "cna",
			Count: totalCNA,
		},
		{
			Value: "N/A",
			Count: totalUnknown,
		},
	}
	sources := make([]es.ResultAggregationCount, 0)
	if source, exists := common["source"]; exists {
		for _, s := range source {
			valueStr := s.Value.(string)
			switch strings.ToLower(valueStr) {
			case "others":
				s.Value = defs.SourceCve
				sources = append(sources, s)
			case "nvd":
				s.Value = defs.SourceCveCraw
				sources = append(sources, s)
			}
		}
	}
	results["source"] = sources
	sort.Sort(model.Float64Aggregations(common["score.global.severity"]))
	severity["all"] = common["score.global.severity"]
	sort.Sort(model.Float64Aggregations(common["score.vti.severity"]))
	results["severity"] = map[string]interface{}{
		"vti": map[string]interface{}{
			"all": common["score.vti.severity"],
		},
		"global": severity,
	}
	queryLanguages := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				queryAll,
				map[string]interface{}{
					"term": map[string]interface{}{
						"languages": defs.LangEN,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"languages": defs.LangVI,
					},
				},
			},
		},
	}
	countLanguages, err := h.elastic.Enrichment().CVE().Count(context.Background(), queryLanguages)
	if err != nil {
		h.logger.Errorf("failed to get languages count. err: %v", err)
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	languages := []es.ResultAggregationCount{
		{
			Value: defs.LangVI,
			Count: 0,
		},
		{
			Value: fmt.Sprintf("%s,%s", defs.LangVI, defs.LangEN),
			Count: countLanguages,
		},
	}
	for _, item := range common["languages"] {
		switch item.Value.(string) {
		case defs.LangVI:
			languages[0].Count = item.Count - countLanguages
		}
	}
	results["languages"] = languages
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(results).Go()
}

func (h *CVEHandler) ExportCveById(c echo.Context) error {
	body, err := h.verifyID(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	bodyPdf := map[string]interface{}{}
	lan := strings.TrimSpace(c.QueryParam("lang"))
	if lan != "vi" && lan != "en" {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log("Bad request lor lang").Go()
	}
	body.ID = strings.TrimSpace(body.ID)
	document, err := h.elastic.Enrichment().CVE().GetByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusNotFound).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	response := &model.CVEVerbose{
		CVE:      *document,
		Products: make([]*model.CPEDetail, 0),
		Clients:  make([]*model.GroupUser, 0),
		CVSS:     map[string]interface{}{},
	}
	languages, err := h.elastic.Enrichment().CVELang("*").FindByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		languages = make([]*model.CVELang, 0)
	}
	description := ""
	for _, language := range languages {
		description = language.Description
		language.Description = language.Raw
		if lan == language.Lang {
			bodyPdf["summary"] = language.Raw
			//if len(language.Raw) != 0 {
			//	bodyPdf["summary"] = language.Raw
			//} else {
			//	bodyPdf["summary"] = "N/A"
			//}
			bodyPdf["reference"] = language.Reference
			//if len(language.Reference) != 0 {
			//	bodyPdf["reference"] = language.Reference
			//} else {
			//	bodyPdf["reference"] = "N/A"
			//}
			bodyPdf["solution"] = language.Patch
			//if len(language.Patch) != 0 {
			//	bodyPdf["solution"] = language.Patch
			//} else {
			//	bodyPdf["solution"] = "N/A"
			//}
		}
	}
	if bodyPdf["solution"] == nil {
		bodyPdf["solution"] = []string{}
	}
	if bodyPdf["reference"] == nil {
		bodyPdf["reference"] = []string{}
	}
	if bodyPdf["summary"] == nil {
		bodyPdf["summary"] = ""
	}
	bodyPdf["lang"] = lan
	bodyPdf["cve_name"] = response.CVE.Name
	bodyPdf["cvss_score"] = response.CVE.Score.Global.Score
	bodyPdf["cvss_severity"] = response.CVE.Score.Global.Severity
	bodyPdf["vcs_severity"] = response.CVE.Score.VTI.Severity
	bodyPdf["cve_owner"] = response.CVE.Vendor
	if response.CVE.Status == defs.AssetStatusCodeApproved {
		bodyPdf["cve_date"] = int(response.CVE.Approved)
	} else {
		bodyPdf["cve_date"] = int(response.CVE.Modified)
	}
	cpeRaw := make([]*model.CPERaw, 0)
	if len(document.Match) > 0 {
		cpeRaw, err = h.GetCPE(document.Match)
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			h.logger.Errorf("failed to get CPE, reason: %v", err)
		}
	}
	listProduct := []string{}
	productMap := make(map[string]struct{})
	cpes := make([]*model.CPERaw, 0)
	for _, cpe := range cpeRaw {
		if cpe != nil {
			productStr := strings.ReplaceAll(cpe.Product, "-", "_")
			productPath := strings.Split(productStr, "_")
			productVerbose := make([]string, 0)
			for _, v := range productPath {
				productVerbose = append(productVerbose, strings.Title(strings.ToLower(v)))
			}
			cpe.Product = strings.Join(productVerbose, " ")
			cpes = append(cpes, cpe)

			if _, ok := productMap[cpe.Product]; !ok {
				productMap[cpe.Product] = struct{}{}
				listProduct = append(listProduct, cpe.Product)
			}
		}
	}
	if len(listProduct) > 3 {
		if len(listProduct) == 0 {
			bodyPdf["cve_product"] = "N/A"
		} else {
			bodyPdf["cve_product"] = strings.Join(listProduct[0:3], ", ") + ", ..."
		}
	} else {
		if len(listProduct) == 0 {
			bodyPdf["cve_product"] = "N/A"
		} else {
			bodyPdf["cve_product"] = strings.Join(listProduct, ", ")
		}
	}
	bodyPdf["products"] = cpes
	raw, err := h.elastic.Enrichment().CVERaw().GetByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	} else {
		switch document.Score.Global.Version {
		case defs.VersionCvssV20:
			response.CVSS = raw.Impact.MetricV2.Vector.Result()
		case defs.VersionCvssV30, defs.VersionCvssV31:
			response.CVSS = raw.Impact.MetricV3.Vector.Result()
		}
	}

	if len(response.CVSS) != 0 {
		bodyPdf["attack_complexity"] = response.CVSS["Attack Complexity"]
		bodyPdf["attack_vector"] = response.CVSS["Attack Vector"]
		bodyPdf["availability_impact"] = response.CVSS["Availability Impact"]
		bodyPdf["base_severity"] = response.CVSS["Base Severity"]
		bodyPdf["confidentiality_impact"] = response.CVSS["Confidentiality Impact"]
		bodyPdf["integrity_impact"] = response.CVSS["Integrity Impact"]
		bodyPdf["privileges_required"] = response.CVSS["Privileges Required"]
		bodyPdf["scope"] = response.CVSS["Scope"]
		bodyPdf["user_interaction"] = response.CVSS["User Interaction"]
	} else {
		bodyPdf["attack_complexity"] = "N/A"
		bodyPdf["attack_vector"] = "N/A"
		bodyPdf["availability_impact"] = "N/A"
		bodyPdf["base_severity"] = "N/A"
		bodyPdf["confidentiality_impact"] = "N/A"
		bodyPdf["integrity_impact"] = "N/A"
		bodyPdf["privileges_required"] = "N/A"
		bodyPdf["scope"] = "N/A"
		bodyPdf["user_interaction"] = "N/A"
	}
	// Call
	client := resty.New()
	client.SetTimeout(time.Minute * 2)
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	res, err := client.R().SetHeader(rest.HeaderContentType, rest.MIMEApplicationJSON).SetBody(bodyPdf).Post(h.config.Api.Route.Export)
	if err != nil || res.StatusCode() != rest.StatusOK {
		h.logger.Debug("Recall api export")
		bodyPdf["summary"] = description
		res, err = client.R().SetHeader(rest.HeaderContentType, rest.MIMEApplicationJSON).SetBody(bodyPdf).Post(h.config.Api.Route.Export)
		if err != nil || res.StatusCode() != rest.StatusOK {
			return c.JSON(http.StatusInternalServerError, err.Error())
		}
	}

	cvename := strings.Split(response.CVE.Name, "-")
	fileName := fmt.Sprintf("CVE_%v_%v.pdf", lan, strings.Join(cvename[1:], "_"))

	c.Response().Header().Set("Content-Type", "application/pdf")
	c.Response().Header().Set("Content-Disposition", "attachment; filename="+fileName)
	c.Response().Header().Set("Content-Transfer-Encoding", "binary")
	if _, err = c.Response().Write(res.Body()); err != nil {
		return nil
	}
	return nil
}

func (h *CVEHandler) GetCPE(match []string) ([]*model.CPERaw, error) {
	result := make([]*model.CPERaw, 0)
	for _, pro := range match {
		saved, err := h.elastic.Enrichment().CPE().FindByValue(context.Background(), pro)
		if err != nil {
			if err.Error() != es.NotFoundError {
				return result, err
			}
			newCPE := model.NewCPE(pro)
			if newCPE != nil {
				saved = &model.CPE{
					CPEDetail: newCPE.CPEDetail,
				}
			}
		}
		if saved != nil {
			result = append(result, &model.CPERaw{
				Part:       saved.CPEDetail.Part,
				References: saved.Reference,
				SwEdition:  saved.SwEdition,
				Version:    saved.CPEDetail.Version,
				ID:         saved.CPEDetail.ID,
				Created:    saved.CPEDetail.Created,
				Value:      saved.CPEDetail.Value,
				Name:       saved.Name,
				Edition:    saved.Edition,
				Other:      saved.Other,
				Creator:    saved.CPEDetail.Creator,
				Vendor:     saved.CPEDetail.Vendor,
				Language:   saved.Language,
				Product:    saved.CPEDetail.Product,
				Update:     saved.CPEDetail.Update,
				TargetSw:   saved.TargetSw,
				TargetHw:   saved.TargetHw,
			})
		}
	}
	return result, nil
}

func (h *CVEHandler) Detail(c echo.Context) error {
	body, err := h.verifyID(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	document, err := h.elastic.Enrichment().CVE().GetByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusNotFound).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if document.Status != defs.StatusCodeApproved {
		document.Approved = 0
	}
	if document.CPEDetails == nil {
		document.CPEDetails = make([]model.CPEMatchDetail, 0)
	}
	if document.CPENodes == nil {
		document.CPENodes = make([]model.CVENode, 0)
	}
	response := &model.CVEVerbose{
		CVE:           *document,
		Products:      make([]*model.CPEDetail, 0),
		Clients:       make([]*model.GroupUser, 0),
		CVSS:          map[string]interface{}{},
		ThreatReports: make([]*model.ThreatReport, 0),
	}
	// Match
	if len(document.Match) > 0 {
		missing := make([]*model.CPEMeta, 0)
		for _, pro := range document.Match {
			saved, err := h.elastic.Enrichment().CPE().FindByValue(context.Background(), pro)
			if err != nil {
				if err.Error() != es.NotFoundError {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
				h.logger.Errorf("failed to get CPE (%s), reason: %v", pro, err)
				newCPE := model.NewCPE(pro)
				if newCPE != nil {
					missing = append(missing, newCPE)
					saved = &model.CPE{
						CPEDetail: newCPE.CPEDetail,
					}
				}
			}
			if saved != nil {
				response.Products = append(response.Products, &saved.CPEDetail)
			}
		}
		if len(missing) > 0 {
			go h.addProduct(missing)
		}
		sort.Sort(model.CPEDetails(response.Products))
	}
	// Group User
	if len(document.Customer) > 0 {
		for _, group := range document.Customer {
			customer := &model.GroupUser{
				TenantID: group,
				Name:     group,
			}
			saved, err := h.mongo.Account().GroupUser().FindByTenantID(group)
			if err != nil {
				h.logger.Errorf("failed to get Group User (%s), reason: %v", group, err)
			} else {
				customer.Name = saved.Name
			}
			response.Clients = append(response.Clients, customer)
		}
		sort.Sort(model.GroupUsers(response.Clients))
	}
	// CVSS
	raw, err := h.elastic.Enrichment().CVERaw().GetByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	} else {
		switch document.Score.Global.Version {
		case defs.VersionCvssV20:
			response.CVSS = raw.Impact.MetricV2.Vector.Result()
		case defs.VersionCvssV30, defs.VersionCvssV31:
			response.CVSS = raw.Impact.MetricV3.Vector.Result()
		case defs.VersionCvssV40:
			response.CVSS = raw.Impact.MetricV4.Vector.Result()
		}
	}
	errGetThreatReport := h.GetThreatReport(document.Name, response)
	if errGetThreatReport != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(errGetThreatReport).Go()
	}
	languages, err := h.elastic.Enrichment().CVELang("*").FindByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		languages = make([]*model.CVELang, 0)
	}
	for _, language := range languages {
		language.Description = language.Raw
		switch language.Lang {
		case defs.LangVI:
			response.MultiLang.VI = language
		case defs.LangEN:
			response.MultiLang.EN = language
		}
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(response).Go()
}

func (h *CVEHandler) GetThreatReport(cveName string, response *model.CVEVerbose) error {
	// Report name
	filter := bson.M{
		"cves":          cveName,
		"approved_time": bson.M{"$ne": 0},
		"status":        defs.ReportStatusApprove,
		"active":        true,
	}

	reports, err := h.mongo.ThreatReport().Find(&filter, []string{"-approved_time"}, 0, 0)
	if err != nil {
		return fmt.Errorf("have error from get threat report %v", err)
	}
	for _, report := range reports {
		var titleVi string
		var titleEn string

		if lang, ok := report.Multilang["vi"]; ok {
			if langMap, ok := lang.(map[string]interface{}); ok {
				if titleVal, ok := langMap["title"]; ok {
					if s, ok := titleVal.(string); ok {
						titleVi = s
					}
				}
			}
		}
		if lang, ok := report.Multilang["en"]; ok {
			if langMap, ok := lang.(map[string]interface{}); ok {
				if titleVal, ok := langMap["title"]; ok {
					if s, ok := titleVal.(string); ok {
						titleEn = s
					}
				}
			}
		}

		response.ThreatReports = append(response.ThreatReports, &model.ThreatReport{
			ApprovedTime: report.ApprovedTime,
			CodeReport:   report.CodeReport,
			ReportName: model.TitleReport{
				Vi: titleVi,
				En: titleEn,
			},
		})
	}
	return nil
}

func (h *CVEHandler) Create(c echo.Context) error {
	body, err := h.verifyCreate(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	editor := c.Get("user_name").(string)
	document, language := body.Generate()
	document.Creator = editor
	_, err = h.elastic.Enrichment().CVE().GetByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	} else {
		return rest.JSON(c).Code(rest.StatusConflict).Go()
	}
	if len(body.Match) == 0 {
		query := body.Product.PrepareQuery()
		products, err := h.elastic.Enrichment().CPE().FindAll(context.Background(), query, []string{})
		if err != nil {
			if err.Error() == es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			products = make([]*model.CPE, 0)
		}
		for _, pro := range products {
			document.Match = append(document.Match, pro.Value)
		}
	}
	document.Vendor = document.GetVendor()
	// Store history
	history := &model.History{
		Created:     document.Created,
		Document:    document.ID,
		Editor:      editor,
		Action:      defs.ActionCreateCVE,
		HistoryType: defs.HistoryTypeSystem,
	}
	history.GenID()
	if err = h.elastic.Enrichment().CVEHistory().Store(context.Background(), history); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Match
	if err = h.match(document); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if document.Affect > 0 {
		isOnlyMass := true
		for _, org := range document.Customer {
			group, err := h.GetGroup(org)
			if err != nil {
				if org != "banking" {
					isOnlyMass = false
					break
				}
				continue
			}
			isExistedPerm := false
			for _, it := range group.Permissions {
				if it == defs.PermissionAutoAlert {
					isExistedPerm = true
					break
				}
			}
			if !isExistedPerm {
				isOnlyMass = false
				break
			}
		}

		if len(document.Customer) == 1 && document.Customer[0] == "banking" {
			isOnlyMass = false
		}

		if isOnlyMass && document.Status == defs.StatusCodeNew {
			document.Status = defs.AssetStatusCodeApproved
			document.Approved = document.Created
		}
	}
	// Save epss on cache
	var score *float64
	if document.EPSS.Score != nil {
		score = document.EPSS.Score
	}
	key := "epss-" + document.Name
	cacheData := CveScoreCache{
		ID:    document.ID,
		Score: score,
	}
	jsonData, _ := json.Marshal(cacheData)
	if err := h.cache.Strings().Set(key, string(jsonData), 0); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Store cve
	if err = h.elastic.Enrichment().CVE().Store(context.Background(), document); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Store language
	if err = h.elastic.Enrichment().CVELang(language.Lang).Store(context.Background(), language); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Publish cve
	//if err = h.publish(&model.CVEDelivery{
	//	CVE:      *document,
	//	Delivery: false,
	//}); err != nil {
	//	return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	//}
	if err = h.createLifecycle(document, &model.CVELifecycle{Source: model.CVE_SOURCE_VTI, Event: model.CVE_EVENT_CREATE_CVE, Creator: editor}); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Cache cve
	if len(document.Match) > 0 {
		if err = h.cache.Strings().Set(document.Name, strings.Join(document.Match, ";"), 0); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	if document.AnalysisTime > 0 {
		if err = h.createLifecycle(document, &model.CVELifecycle{Source: model.CVE_SOURCE_VTI, Event: model.CVE_EVENT_ANALYSIS_TIME, Creator: editor}); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(document.ID).Go()
}

func (h *CVEHandler) Edit(c echo.Context) error {
	body, err := h.verifyEdit(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	editor := c.Get("user_name").(string)
	saved, err := h.elastic.Enrichment().CVE().GetByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusNotFound).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	oldEPSSScore := saved.EPSS.Score
	oldEPSSPercentile := saved.EPSS.Percentile
	saved.EPSS = *body.EPSS
	saved.CWE = body.CWE
	now, _ := clock.Now(clock.Local)
	saved.Modified = clock.UnixMilli(now)
	saved.Published = body.Published

	if len(body.Match) == 0 {
		query := body.Product.PrepareQuery()
		products, err := h.elastic.Enrichment().CPE().FindAll(context.Background(), query, []string{})
		if err != nil {
			if err.Error() == es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			products = make([]*model.CPE, 0)
		}
		for _, pro := range products {
			saved.Match = append(saved.Match, pro.Value)
		}
	} else {
		saved.Match = body.Match
	}
	saved.Vendor = saved.GetVendor()
	if saved.Status == defs.StatusCodeReject {
		saved.Status = defs.StatusCodeNew
		saved.OldStatus = defs.StatusCodeReject
	}
	language, err := h.elastic.Enrichment().CVELang(body.Lang).GetByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	if language == nil {
		language = &model.CVELang{
			ID:        saved.ID,
			Lang:      body.Lang,
			Reference: []string{},
			Patch:     []string{},
		}
	}
	language.Description = strings.TrimSpace(html2text.HTML2Text(body.Description))
	language.Raw = body.Description
	language.Reference = strings.Split(body.Reference, "\n")
	language.Patch = strings.Split(body.Patch, "\n")
	globalSet := false
	if strings.HasPrefix(body.CVSS.CVSS2.Version, "2.") {
		cvssV2 := model.CVEMetric{
			Score:        body.CVSS.CVSS2.Score,
			Version:      body.CVSS.CVSS2.Version,
			VectorString: body.CVSS.CVSS2.VectorString,
			Source:       body.CVSS.CVSS2.Source,
		}
		for severity, point := range defs.RangeCvssV2SeverityScore {
			rPoint := point.(map[string]float32)
			if body.CVSS.CVSS2.Score >= rPoint["gte"] && body.CVSS.CVSS2.Score <= rPoint["lte"] {
				cvssV2.Severity = severity
				break
			}
		}
		saved.Score.CVSS2 = cvssV2
		saved.Score.Global = cvssV2
		globalSet = true
	} else if body.CVSS.CVSS2.Version == "" {
		saved.Score.CVSS2 = model.CVEMetric{}
	}
	if strings.HasPrefix(body.CVSS.CVSS3.Version, "3.") {
		cvssV3 := model.CVEMetric{
			Score:        body.CVSS.CVSS3.Score,
			Version:      body.CVSS.CVSS3.Version,
			VectorString: body.CVSS.CVSS3.VectorString,
			Source:       body.CVSS.CVSS3.Source,
		}
		for severity, point := range defs.RangeCvssV3SeverityScore {
			rPoint := point.(map[string]float32)
			if body.CVSS.CVSS3.Score >= rPoint["gte"] && body.CVSS.CVSS3.Score <= rPoint["lte"] {
				cvssV3.Severity = severity
				break
			}
		}
		saved.Score.CVSS3 = cvssV3
		saved.Score.Global = cvssV3
		globalSet = true
	} else if body.CVSS.CVSS3.Version == "" {
		saved.Score.CVSS3 = model.CVEMetric{}
	}
	if strings.HasPrefix(body.CVSS.CVSS4.Version, "4.") {
		cvssV4 := model.CVEMetric{
			Score:        body.CVSS.CVSS4.Score,
			Version:      body.CVSS.CVSS4.Version,
			VectorString: body.CVSS.CVSS4.VectorString,
			Source:       body.CVSS.CVSS4.Source,
		}
		for severity, point := range defs.RangeCvssV4SeverityScore {
			rPoint := point.(map[string]float32)
			if body.CVSS.CVSS4.Score >= rPoint["gte"] && body.CVSS.CVSS4.Score <= rPoint["lte"] {
				cvssV4.Severity = severity
				break
			}
		}
		saved.Score.CVSS4 = cvssV4
		saved.Score.Global = cvssV4
		globalSet = true
	} else if body.CVSS.CVSS4.Version == "" {
		saved.Score.CVSS4 = model.CVEMetric{}
	}
	if body.CVSS.CNA.Version != "" {
		cna := model.ProcessCVSSCNA(
			body.CVSS.CNA.Score,
			body.CVSS.CNA.Version,
			body.CVSS.CNA.VectorString,
			body.CVSS.CNA.Source,
		)

		saved.Score.CNA = cna
		if !globalSet {
			saved.Score.Global = cna
			globalSet = true
		}
	} else {
		saved.Score.CNA = model.CVEMetric{}
	}
	if !globalSet {
		saved.Score.Global = model.CVEMetric{}
	}
	// Store cve lang
	if err = h.elastic.Enrichment().CVELang(body.Lang).Store(context.Background(), language); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Store history
	history := &model.History{
		Created:     saved.Modified,
		Document:    saved.ID,
		Editor:      editor,
		Action:      defs.ActionEditCVE,
		HistoryType: defs.HistoryTypeSystem,
	}
	history.GenID()
	if err = h.elastic.Enrichment().CVEHistory().Store(context.Background(), history); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	newEPSSScore := saved.EPSS.Score
	newEPSSPercentile := saved.EPSS.Percentile
	if (oldEPSSScore == nil && newEPSSScore != nil) ||
		(oldEPSSScore != nil && newEPSSScore == nil) ||
		(oldEPSSScore != nil && newEPSSScore != nil && *oldEPSSScore != *newEPSSScore) {
		epssHistory := &model.CVEEPSSHistory{
			CVEName:       saved.Name,
			Date:          saved.Modified,
			Editor:        editor,
			OldScore:      oldEPSSScore,
			NewScore:      newEPSSScore,
			OldPercentile: oldEPSSPercentile,
			NewPercentile: newEPSSPercentile,
		}
		epssHistory.GenID()
		if err = h.elastic.Enrichment().CVEEPSSHistory().Store(context.Background(), epssHistory); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		key := "epss-" + saved.Name
		var score *float64
		if newEPSSScore != nil {
			score = newEPSSScore
		}
		cacheData := CveScoreCache{
			ID:    saved.ID,
			Score: score,
		}
		jsonData, _ := json.Marshal(cacheData)
		if err := h.cache.Strings().Set(key, string(jsonData), 0); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		h.logger.Infof("Successfully updated cache for CVE %s: score %f", saved.Name, newEPSSScore)
	}
	// Match
	oldAnalysisTime := saved.AnalysisTime
	if err = h.match(saved); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	isApprovedCve := false
	if saved.Affect > 0 {
		isOnlyMass := true
		for _, org := range saved.Customer {
			group, err := h.GetGroup(org)
			if err != nil {
				if org != "banking" {
					isOnlyMass = false
					break
				}
				continue
			}
			isExistedPerm := false
			for _, it := range group.Permissions {
				if it == defs.PermissionAutoAlert {
					isExistedPerm = true
					break
				}
			}
			if !isExistedPerm {
				isOnlyMass = false
				break
			}
		}
		if len(saved.Customer) == 1 && saved.Customer[0] == "banking" {
			isOnlyMass = false
		}
		if isOnlyMass && saved.Status == defs.StatusCodeNew {
			saved.Status = defs.AssetStatusCodeApproved
			saved.Approved = clock.UnixMilli(now)
			isApprovedCve = true
		}
	}
	if saved.Status == defs.StatusCodeReject {
		if saved.Affect == 0 {
			saved.Status = defs.StatusCodeUnknown
		} else {
			saved.Status = defs.StatusCodeNew
		}
	}
	// Store cve
	switch body.Lang {
	case defs.LangVI:
		saved.Searchable.VI.Description = language.Description
		saved.Searchable.VI.Reference = language.Reference
	case defs.LangEN:
		saved.Searchable.EN.Description = language.Description
		saved.Searchable.EN.Reference = language.Reference
	}
	saved.Languages = slice.String(append(saved.Languages, body.Lang)).Unique().Extract()
	if err = h.elastic.Enrichment().CVE().Store(context.Background(), saved); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Publish cve
	//if err = h.publish(&model.CVEDelivery{
	//	CVE:      *saved,
	//	Delivery: false,
	//}); err != nil {
	//	return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	//}
	// Create lifecycle
	if isApprovedCve {
		if err = h.createLifecycle(saved, &model.CVELifecycle{
			Source:  model.CVE_SOURCE_VTI,
			Event:   model.CVE_EVENT_APPROVE_CVE,
			Creator: editor,
		}); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	if oldAnalysisTime == 0 && saved.AnalysisTime > 0 {
		if err = h.createLifecycle(saved, &model.CVELifecycle{
			Source:  model.CVE_SOURCE_VTI,
			Event:   model.CVE_EVENT_ANALYSIS_TIME,
			Creator: editor,
		}); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	if len(saved.Match) > 0 {
		if err = h.cache.Strings().Set(saved.Name, strings.Join(saved.Match, ";"), 0); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	return rest.JSON(c).Code(rest.StatusOK).Body(saved.ID).Go()
}

func (h *CVEHandler) Exist(c echo.Context) error {
	body, err := h.verifyID(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	_, err = h.elastic.Enrichment().CVE().GetByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusOK).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	} else {
		return rest.JSON(c).Code(rest.StatusConflict).Go()
	}
}

func (h *CVEHandler) CVEHistory(c echo.Context) error {
	body, err := h.verifyHistory(c)
	if err != nil {
		return rest.JSON(c).Code(http.StatusBadRequest).Body(map[string]any{"error": err.Error()}).Go()
	}
	query := body.PrepareQuery()
	histories, total, err := h.elastic.Enrichment().CVEHistory().Find(context.Background(), query, []string{"-created"}, body.Offset, body.Size)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(http.StatusInternalServerError).Body(map[string]any{"error": err.Error()}).Go()
		}
		return rest.JSON(c).Code(http.StatusOK).Body(map[string]any{"data": make([]any, 0), "total": 0}).Go()
	}
	results := make([]*model.HistoryListItem, 0, len(histories))
	for _, history := range histories {
		results = append(results, &model.HistoryListItem{
			ID:          history.ID,
			Created:     history.Created,
			Document:    history.Document,
			Editor:      history.Editor,
			Action:      history.Action,
			Description: history.Description,
			HistoryType: history.HistoryType,
		})
	}
	// Success
	return rest.JSON(c).Code(http.StatusOK).Body(model.HistoryResponse{
		Data:  results,
		Total: total,
	}).Go()
}

func (h *CVEHandler) EPSSHistory(c echo.Context) error {
	body, err := h.verifyHistoryEPSS(c)
	if err != nil {
		return rest.JSON(c).Body(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.PrepareQuery()
	results, total, err := h.elastic.Enrichment().CVEEPSSHistory().Find(context.Background(), query, []string{"-date"}, body.Offset, body.Size)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Body(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]any{"data": make([]any, 0), "total": 0}).Go()
	}
	return rest.JSON(c).Code(http.StatusOK).Body(model.HistoryEPSSResponse{
		Data:  results,
		Total: total,
	}).Go()
}

func (h *CVEHandler) Confirm(c echo.Context) error {
	body, err := h.verifyConfirm(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	editor := c.Get("user_name").(string)
	saved, err := h.elastic.Enrichment().CVE().GetByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusNotFound).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	history := getHistory(body, saved, editor)
	if history == nil {
		return rest.JSON(c).Code(rest.StatusOK).Go()
	}
	history.GenID()
	if err = h.elastic.Enrichment().CVEHistory().Store(context.Background(), history); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Match
	if err = h.match(saved); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Store cve
	if err = h.elastic.Enrichment().CVE().Store(context.Background(), saved); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Publish cve
	if err = h.publish(&model.CVEDelivery{
		CVE:      *saved,
		Delivery: body.Status == defs.StatusCodeApproved,
	}); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}

	// Create lifecycle
	if err = h.createLifecycle(saved, &model.CVELifecycle{Source: model.CVE_SOURCE_VTI, Event: model.CVE_EVENT_APPROVE_CVE, Creator: editor}); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Go()
}

func (h *CVEHandler) processCveCustomer(ctx context.Context, saved *model.CVE) error {
	if saved.Status == defs.StatusCodeApproved {
		newOrgs := getDiffOrganinations(saved.Organizations, saved.Customer)
		saved.Organizations = append(saved.Organizations, newOrgs...)
		if err := h.bulkInsertCveCustomer(ctx, saved.Organizations, saved.Name); err != nil {
			h.logger.Infof("failed bulkInsertCveCustomer: %v\n", err)
			return err
		}
	}
	return nil
}

func (h *CVEHandler) deleteCveCustomer(ctx context.Context, data map[string]struct{}, cveId string) error {
	if len(data) == 0 {
		return nil
	}
	g, ctx := errgroup.WithContext(ctx)
	for tenantId := range data {
		g.Go(func() error {
			query := map[string]any{
				"bool": map[string]any{
					"filter": []any{
						map[string]any{
							"term": map[string]any{
								"tenant_id": tenantId,
							},
						},
						map[string]any{
							"term": map[string]any{
								"cve_id": cveId,
							},
						},
					},
				},
			}
			return h.elastic.Enrichment().CVECustomer().BulkDelete(ctx, query)
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	return nil
}

func (h *CVEHandler) bulkInsertCveCustomer(ctx context.Context, data []model.Organization, cveId string) error {
	if len(data) == 0 {
		return nil
	}
	query := map[string]any{
		"term": map[string]any{
			"cve_id": cveId,
		},
	}
	oldCveCustomers, err := h.elastic.Enrichment().CVECustomer().Find(ctx, query)
	if err != nil && err.Error() != es.NotFoundError {
		return err
	}
	mapOldCveCustomer := make(map[string]struct{})
	for _, elem := range oldCveCustomers {
		mapOldCveCustomer[elem.TenantID] = struct{}{}
	}
	docs := make([]*model.CveCustomer, 0)
	for _, elem := range data {
		if _, ok := mapOldCveCustomer[elem.TenantId]; !ok {
			row := &model.CveCustomer{
				TenantID:     elem.TenantId,
				ApprovalTime: elem.ApprovalTime,
				Modified:     time.Now().UnixMilli(),
				CveID:        cveId,
			}
			row.GenID(cveId, elem.TenantId)
			docs = append(docs, row)
		}
	}
	if len(docs) == 0 {
		h.logger.Infof("empty new cve customers: %s", cveId)
		return nil
	}
	return h.elastic.Enrichment().CVECustomer().BulkInsert(ctx, docs)
}

func getDiffOrganinations(oldData []model.Organization, newData []string) []model.Organization {
	oldDelivered := make(map[string]struct{})
	for _, org := range oldData {
		oldDelivered[org.TenantId] = struct{}{}
	}
	newOrgs := make([]model.Organization, 0)
	for _, org := range newData {
		if _, ok := oldDelivered[org]; !ok {
			newOrgs = append(newOrgs, model.Organization{
				ApprovalTime: time.Now().UnixMilli(),
				TenantId:     org,
			})
		}
	}
	return newOrgs
}

func getHistory(body model.RequestCVEConfirm, saved *model.CVE, editor string) *model.History {
	now, _ := clock.Now(clock.Local)
	nowMilli := now.UnixMilli()
	if saved.Status != body.Status {
		saved.AnalyzedTime = nowMilli
		saved.OldStatus = saved.Status
		saved.ReasonChangeStatus = body.Description
		if body.Status == defs.StatusCodeApproved {
			saved.Approved = nowMilli
		} else if body.Status == defs.StatusCodeReject && saved.Status == defs.StatusCodeApproved {
			saved.Approved = 0
		}
	}
	if body.Status == defs.StatusCodeApproved {
		if body.Checklist.Metric.EQ(saved.Checklist.Metric) && saved.Status == body.Status {
			logger.Infof("body.Checklist.Metric.EQ(saved.Checklist.Metric) && saved.Status == body.Status")
			return nil
		}
		saved.Checklist = body.Checklist
		saved.Score.VTI.Score = float32(body.Checklist.Point)
		saved.Score.VTI.SetVTIMetric()
		saved.Status = body.Status
	} else if body.Status == defs.StatusCodeReject {
		saved.Status = body.Status
	}
	saved.Modified = nowMilli
	saved.Checker = editor
	historyAction := ""
	switch saved.Status {
	case defs.StatusCodeApproved:
		if saved.Approved == 0 {
			historyAction = defs.ActionApproveCVE
			saved.Approved = saved.Modified
			saved.ApprovedFirst = saved.Approved
			saved.History = append(saved.History, model.SeverityMetric{
				Created:  nowMilli,
				Severity: saved.Score.VTI.Severity,
				Type:     defs.HistorySeverityNewType,
			})
		} else {
			historyAction = defs.ActionApproveCVE
			saved.History = append(saved.History, model.SeverityMetric{
				Created:  nowMilli,
				Severity: saved.Score.VTI.Severity,
				Type:     defs.HistorySeverityUpdateType,
			})
		}
	case defs.StatusCodeReject:
		historyAction = defs.ActionRejectCVE
	}
	return &model.History{
		Created:  saved.Modified,
		Document: saved.ID, Editor: editor,
		Description: body.Description,
		Action:      historyAction,
		HistoryType: defs.HistoryTypeSystem,
	}
}

func (h *CVEHandler) createLifecycle(document *model.CVE, req *model.CVELifecycle) error {
	now, _ := clock.Now(clock.Local)
	created := clock.UnixMilli(now)
	req.Created = created
	req.CVEId = document.ID
	req.CVECode = document.Name
	req.GenerateId(document.ID)

	return h.elastic.Enrichment().CVELifecycle().Store(context.Background(), req)
}

func (h *CVEHandler) CreateLifecycle(c echo.Context) error {
	body, err := h.verifyCreateLifecycle(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	doc, err := h.elastic.Enrichment().CVE().GetByID(context.Background(), body.ID)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusNotFound).Go()
	}
	if err = h.createLifecycle(doc, &model.CVELifecycle{Source: body.Source, Event: body.Event}); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}

	return rest.JSON(c).Code(rest.StatusOK).Go()
}

func (h *CVEHandler) CVELifeCycleV2(c echo.Context) error {
	body, err := h.verifyCVELifeCycleV2(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.PrepareQuery()
	results, total, err := h.elastic.Enrichment().CVELifeCycleV2().Find(context.Background(), query, []string{"-created"}, body.Offset, body.Size)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]any{"data": make([]any, 0), "total": 0}).Go()
	}
	return rest.JSON(c).Code(http.StatusOK).Body(model.CVELifecycleV2Response{
		Data:  results,
		Total: total,
	}).Go()
}

func (h *CVEHandler) CheckReject(c echo.Context) error {
	body, err := h.verifySearch(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}

	if body.Time.Approved.Gte > 0 || body.Time.Approved.Lte > 0 {
		if len(body.Status) > 1 || (len(body.Status) == 1 && body.Status[0] != 2) {
			return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"message": "True"}).Go()
		}
	}
	query := body.PrepareQuery()
	results, err := h.elastic.Enrichment().CVE().Find(context.Background(), query, body.Sort, body.Offset, body.Size)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	for _, cve := range results {
		if cve.Status != defs.StatusCodeNew {
			err = errors.New(fmt.Sprintf("invalid status cve %s", cve.Name))
			return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"message": "False"}).Go()
		}
	}
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"message": "True"}).Go()
}

func (h *CVEHandler) RejectCVEs(c echo.Context) error {
	body, err := h.verifyRejectCVEs(c)
	body.Status = defs.StatusCodeReject
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}

	if len(body.IDs) == 0 {
		err = h.verifySearchFilter(body.Filter)
		if err != nil {
			return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
		}
	}

	editor := c.Get("user_name").(string)
	listCVE, err := h.FetchCVEs(&body.RequestCVECommon)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if len(listCVE) == 0 {
		return rest.JSON(c).Code(rest.StatusNotFound).Go()
	}

	for _, cve := range listCVE {
		if cve.Status != defs.StatusCodeNew {
			err = errors.New(fmt.Sprintf("invalid status cve %s", cve.Name))
			return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
		}
	}

	group, _ := errgroup.WithContext(context.Background())
	type results struct {
		err   error
		value *model.CVE
	}
	result := make(chan results)
	group.Go(func() error {
		wg := sync.WaitGroup{}
		pool, _ := ants.NewPoolWithFunc(h.config.App.Core, func(i interface{}) {
			saved := i.(*model.CVE)
			defer wg.Done()
			defer func() {
				rs := results{
					err:   err,
					value: saved,
				}
				result <- rs
			}()
			now, _ := clock.Now(clock.Local)
			saved.Modified = clock.UnixMilli(now)
			saved.OldStatus = defs.StatusCodeNew
			saved.Status = body.Status
			saved.Checker = editor
			saved.AnalyzedTime = clock.UnixMilli(now)
			saved.Approved = 0
			// Store history
			history := &model.History{
				Created:     saved.Modified,
				Document:    saved.ID,
				Editor:      editor,
				Description: body.Description,
			}
			history.GenID()
			history.Action = defs.ActionRejectCVE
			history.HistoryType = defs.HistoryTypeSystem

			if err = h.elastic.Enrichment().CVEHistory().Store(context.Background(), history); err != nil {
				return
			}
			// Match
			if err = h.match(saved); err != nil {
				return
			}
			// Store cve
			if err = h.elastic.Enrichment().CVE().Store(context.Background(), saved); err != nil {
				return
			}
			// Publish cve
			if err = h.publish(&model.CVEDelivery{
				CVE:      *saved,
				Delivery: body.Status == defs.StatusCodeApproved,
			}); err != nil {
				return
			}
		})
		defer pool.Release()

		for _, cve := range listCVE {
			wg.Add(1)
			if err := pool.Invoke(cve); err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}
		wg.Wait()
		close(result)
		return nil
	})
	group.Go(func() error {
		for value := range result {
			if value.err != nil {
				if err.Error() != es.NotFoundError {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
			}
		}
		return nil
	})
	err = group.Wait()
	if err != nil {
		return err
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(body.IDs).Go()
}

func (h *CVEHandler) CVEsInternalFlag(c echo.Context) error {
	body, err := h.verifyInternalFlagCVEs(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	if len(body.IDs) == 0 {
		err = h.verifySearchFilter(body.Filter)
		if err != nil {
			return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
		}
	}
	now, _ := clock.Now(clock.Local)
	if body.Action == defs.MarkInternalFlag {
		query := map[string]interface{}{
			"terms": map[string]interface{}{
				"flag_name.raw": body.FlagsName,
			},
		}
		listFlags, _, err := h.elastic.Enrichment().CVEInternalFlag().Find(context.Background(), query, []string{}, 0, len(body.FlagsName))
		if err != nil && err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		if err != nil && err.Error() == es.NotFoundError {
			listFlags = []*model.CVEInternalFlag{}
		}
		existedFlag := make(map[string]struct{})
		for _, flag := range listFlags {
			existedFlag[flag.FlagName] = struct{}{}
		}
		internalFlags := make([]*model.CVEInternalFlag, 0, len(body.FlagsName))
		for _, flag := range body.FlagsName {
			if _, found := existedFlag[flag]; !found {
				internalFlag := &model.CVEInternalFlag{
					FlagName: flag,
					Date:     clock.UnixMilli(now),
				}
				internalFlag.GenID()
				internalFlags = append(internalFlags, internalFlag)
			}
		}
		if len(internalFlags) > 0 {
			if err := h.elastic.Enrichment().CVEInternalFlag().
				StoreAll(context.Background(), internalFlags); err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}
	}
	editor := c.Get("user_name").(string)
	listCVE, err := h.FetchCVEs(&body.RequestCVECommon)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if len(listCVE) == 0 {
		return rest.JSON(c).Code(rest.StatusNotFound).Go()
	}
	group, _ := errgroup.WithContext(context.Background())
	type results struct {
		err   error
		value *model.CVE
	}
	result := make(chan results)
	group.Go(func() error {
		wg := sync.WaitGroup{}
		pool, _ := ants.NewPoolWithFunc(h.config.App.Core, func(i any) {
			saved := i.(*model.CVE)
			defer wg.Done()
			defer func() {
				rs := results{
					err:   err,
					value: saved,
				}
				result <- rs
			}()
			saved.Modified = clock.UnixMilli(now)
			// Store history
			history := &model.History{
				Created:  saved.Modified,
				Document: saved.ID,
				Editor:   editor,
			}
			history.GenID()
			history.HistoryType = defs.HistoryTypeSystem
			shouldSaveHistory := false
			if body.Action == defs.MarkInternalFlag {
				hasNewFlag := false
				for _, flag := range body.FlagsName {
					if !sliceContains(saved.InternalFlag, flag) {
						hasNewFlag = true
						if flag != "" {
							saved.InternalFlag = append(saved.InternalFlag, flag)
						}
					}
				}
				if hasNewFlag {
					history.Action = defs.ActionMarkInternalFlag
					shouldSaveHistory = true
				}
			} else if body.Action == defs.DeleteInternalFlag {
				hasValidFlag := false
				var flagsToRemove []string
				for _, clientFlag := range body.FlagsName {
					if sliceContains(saved.InternalFlag, clientFlag) {
						hasValidFlag = true
						flagsToRemove = append(flagsToRemove, clientFlag)
					}
				}
				if hasValidFlag {
					saved.InternalFlag = filterTags(saved.InternalFlag, flagsToRemove)
					history.Action = defs.ActionDeleteInternalFlag
					shouldSaveHistory = true
				} else {
					shouldSaveHistory = false
				}
			}
			if shouldSaveHistory {
				if err = h.elastic.Enrichment().CVEHistory().Store(context.Background(), history); err != nil {
					return
				}
			}
			if err = h.elastic.Enrichment().CVE().Store(context.Background(), saved); err != nil {
				return
			}
		})
		defer pool.Release()
		for _, cve := range listCVE {
			wg.Add(1)
			if err := pool.Invoke(cve); err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}
		wg.Wait()
		close(result)
		return nil
	})
	group.Go(func() error {
		for value := range result {
			if value.err != nil {
				if err.Error() != es.NotFoundError {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
			}
		}
		return nil
	})
	err = group.Wait()
	if err != nil {
		return err
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(body.IDs).Go()
}

func (h *CVEHandler) SearchInternalFlag(c echo.Context) error {
	body, err := h.verifySearchInternalFlag(c)
	if err != nil {
		return rest.JSON(c).Code(http.StatusBadRequest).Body(map[string]any{"error": err.Error()}).Go()
	}
	query := body.PrepareQuery()
	results, total, err := h.elastic.Enrichment().CVEInternalFlag().Find(context.Background(), query, []string{"-date"}, body.Offset, body.Size)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(http.StatusInternalServerError).Body(map[string]any{"error": err.Error()}).Go()
		}
		return rest.JSON(c).Code(http.StatusOK).Body(map[string]any{"data": make([]any, 0), "total": 0}).Go()
	}
	return rest.JSON(c).Code(http.StatusOK).Body(model.InternalFlagResponse{
		Data:  results,
		Total: total,
	}).Go()
}

func (h *CVEHandler) publish(document *model.CVEDelivery) error {
	bts, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if err := h.queue.Publish("", defs.QueueCVEAnalyzer, rabbit.Message{
		Body:        bts,
		ContentType: rabbit.MIMEApplicationJSON,
		Mode:        rabbit.Persistent,
	}); err != nil {
		return err
	}
	// Success
	return nil
}

func (h *CVEHandler) match(document *model.CVE) error {
	// Analyzer cve
	h.mutex.Lock()
	defer func() {
		h.mutex.Unlock()
	}()
	match := make([]string, 0)
	for _, m := range document.Match {
		actual, err := cpe.NewItemFromFormattedString(m)
		if err != nil {
			h.logger.Errorf("failed to parse cpe (%s), reason: %v", m, err)
			continue
		}
		if !slice.String(document.ProductType).Contains(string(actual.Part())) {
			document.ProductType = append(document.ProductType, string(actual.Part()))
		}
		for org, assets := range h.assets {
			for _, asset := range assets {
				if cpe.CheckSuperset(asset, actual, true) || cpe.CheckSubset(asset, actual, true) {
					if !slice.String(match).Contains(org) {
						match = append(match, org)
					}
					break
				}
			}
		}
	}
	document.Customer = match
	document.Affect = int64(len(match))
	if document.Status == defs.StatusCodeUnknown || document.Status == defs.StatusCodeNew {
		if document.Affect > 0 {
			document.Status = defs.StatusCodeNew
		} else {
			document.Status = defs.StatusCodeUnknown
		}
	}
	if document.AnalysisTime == 0 &&
		(document.Score.Global.Version == defs.VersionCvssV30 ||
			document.Score.Global.Version == defs.VersionCvssV31 ||
			document.Score.Global.Version == defs.VersionCvssV40) &&
		document.Affect > 0 && (document.Score.Global.Score == 0 || document.Score.Global.Score >= 7) {
		document.AnalysisTime = document.Modified
	}
	if err := h.processCveCustomer(context.Background(), document); err != nil {
		return err
	}
	// Success
	return nil
}

func (h *CVEHandler) verifySearch(c echo.Context) (body model.RequestCVESearch, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	err = body.Verify()
	if err != nil {
		return body, err
	}
	// Success
	return body, nil
}

func (h *CVEHandler) verifyLifeCycleCVE(c echo.Context) (body model.RequestLifeCycleCVE, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if len(body.CVECode) == 0 {
		body.CVECode = make([]string, 0)
	}
	// Success
	return body, nil
}

func (h *CVEHandler) verifyExport(c echo.Context) (body model.RequestExport, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	err = body.Req.Verify()
	if err != nil {
		return body, err
	}
	// Success
	return body, nil
}

func (h *CVEHandler) verifyStatistic(c echo.Context) (body model.RequestCVEStatistic, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if body.Checker != "" {
		body.Checker = strings.ToLower(body.Checker)
	}
	flagsName := make([]string, 0)
	for _, flag := range body.InternalFlags {
		trimmed := strings.TrimSpace(flag)
		if trimmed != "" {
			flagsName = append(flagsName, trimmed)
		}
	}
	body.InternalFlags = flagsName
	// Success
	return body, nil
}

func (h *CVEHandler) verifyID(c echo.Context) (body model.RequestCVEID, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.ID = strings.ToUpper(body.ID)
	re := regexp.MustCompile(defs.RegexCVE)
	if re.MatchString(body.ID) {
		body.ID = hash.SHA1(strings.ToUpper(body.ID))
	} else {
		body.ID = strings.ToLower(body.ID)
	}
	// Success
	return body, nil
}

func (h *CVEHandler) verifyCreate(c echo.Context) (bodyRequestCVECreate model.RequestCVECreate, err error) {
	if err = Validate(c, &bodyRequestCVECreate); err != nil {
		log.Printf("Validate error: %v", err)
		return bodyRequestCVECreate, err
	}
	bodyRequestCVECreate.ID, err = validateCVEID(bodyRequestCVECreate.ID)
	if err != nil {
		return bodyRequestCVECreate, err
	}
	if len(bodyRequestCVECreate.Match) == 0 {
		bodyRequestCVECreate.Match = make([]string, 0)
	}
	bodyRequestCVECreate.CVSS, err = validateCVSS(bodyRequestCVECreate.CVSS)
	if err != nil {
		return bodyRequestCVECreate, err
	}
	if err := validateEPSS(bodyRequestCVECreate.EPSS); err != nil {
		return bodyRequestCVECreate, err
	}
	bodyRequestCVECreate.CWE, err = validateCWE(bodyRequestCVECreate.CWE)
	if err != nil {
		return bodyRequestCVECreate, err
	}
	bodyRequestCVECreate.Lang, err = validateLanguage(bodyRequestCVECreate.Lang)
	if err != nil {
		return bodyRequestCVECreate, err
	}
	return bodyRequestCVECreate, nil
}

func (h *CVEHandler) verifyEdit(c echo.Context) (body model.RequestCVEEdit, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.ID, err = validateCVEID(body.ID)
	if err != nil {
		return body, err
	}
	body.ID = hash.SHA1(body.ID)
	if len(body.Match) == 0 {
		body.Match = make([]string, 0)
	}
	body.CVSS, err = validateCVSS(body.CVSS)
	if err != nil {
		return body, err
	}
	if err := validateEPSS(body.EPSS); err != nil {
		return body, err
	}
	body.CWE, err = validateCWE(body.CWE)
	if err != nil {
		return body, err
	}
	body.Lang, err = validateLanguage(body.Lang)
	if err != nil {
		return body, err
	}
	return body, nil
}

func (h *CVEHandler) verifyHistory(c echo.Context) (bodyHistory model.RequestHistorySearch, err error) {
	if err = Validate(c, &bodyHistory); err != nil {
		return bodyHistory, err
	}
	bodyHistory.ID = strings.ToLower(bodyHistory.ID)
	if strings.Contains(bodyHistory.ID, "cve-") {
		bodyHistory.ID = hash.SHA1(strings.ToUpper(bodyHistory.ID))
	}
	invalidDateRangeHistory := bodyHistory.FromDate < 0 || bodyHistory.ToDate < 0 ||
		(bodyHistory.FromDate > 0 && bodyHistory.ToDate == 0) ||
		(bodyHistory.FromDate == 0 && bodyHistory.ToDate > 0) ||
		(bodyHistory.FromDate > 0 && bodyHistory.ToDate > 0 && bodyHistory.FromDate > bodyHistory.ToDate)
	if invalidDateRangeHistory {
		return bodyHistory, fmt.Errorf("both from date and to date must be provided together, must be non negative, and from date must be less than or equal to to date")
	}
	if bodyHistory.Size == 0 {
		bodyHistory.Size = 10
	}
	// Success
	return bodyHistory, nil
}

func (h *CVEHandler) verifyHistoryEPSS(c echo.Context) (body model.RequestEPSSHistorySearch, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.ID = strings.TrimSpace(strings.ToUpper(body.ID))
	if !strings.Contains(body.ID, "CVE-") {
		return body, fmt.Errorf("ID must start with 'CVE-' prefix")
	}
	invalidDateRange := body.FromDate < 0 || body.ToDate < 0 ||
		(body.FromDate > 0 && body.ToDate == 0) ||
		(body.FromDate == 0 && body.ToDate > 0) ||
		(body.FromDate > 0 && body.ToDate > 0 && body.FromDate > body.ToDate)
	if invalidDateRange {
		return body, fmt.Errorf("both from date and to date must be provided together, must be non negative, and from date must be less than or equal to to date")
	}
	if body.Size == 0 {
		body.Size = 10
	}
	// Success
	return body, nil
}

func (h *CVEHandler) verifyConfirm(c echo.Context) (body model.RequestCVEConfirm, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.ID = strings.ToLower(body.ID)
	if strings.Contains(body.ID, "cve-") {
		body.ID = hash.SHA1(strings.ToUpper(body.ID))
	}
	if body.Status != defs.StatusCodeApproved && body.Status != defs.StatusCodeReject {
		return body, errors.New("invalid value for parameter <status>")
	}

	if body.Status == defs.StatusCodeReject {
		return body, nil
	}

	if body.Checklist.Metric.Ability == defs.PointNil {
		return body, errors.New("invalid value for parameter <checklist.metric.ability>")
	}
	if body.Checklist.Metric.Affect == defs.PointNil {
		return body, errors.New("invalid value for parameter <checklist.metric.affect>")
	}
	if body.Checklist.Metric.Condition == defs.PointNil {
		return body, errors.New("invalid value for parameter <checklist.metric.condition>")
	}
	if body.Checklist.Metric.Patch == defs.PointNil {
		return body, errors.New("invalid value for parameter <checklist.metric.patch>")
	}
	if body.Checklist.Metric.Exploit == defs.PointNil {
		return body, errors.New("invalid value for parameter <checklist.metric.exploit>")
	}

	if body.Checklist.Metric.Calculate() != body.Checklist.Point {
		return body, errors.New("wrong checklist point")
	}
	// Success
	return body, nil
}

func (h *CVEHandler) verifyCreateLifecycle(c echo.Context) (body model.CreateLifecycleRequest, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.ID = strings.ToUpper(body.ID)
	re := regexp.MustCompile(defs.RegexCVE)
	if re.MatchString(body.ID) {
		body.ID = hash.SHA1(strings.ToUpper(body.ID))
	}
	return body, err
}

func (h *CVEHandler) verifyCVELifeCycleV2(c echo.Context) (body model.RequestCVELifeCycleV2Search, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.ID = strings.ToLower(body.ID)
	if strings.Contains(body.ID, "cve-") {
		body.ID = hash.SHA1(strings.ToUpper(body.ID))
	}
	invalidDateRange := body.FromDate < 0 || body.ToDate < 0 ||
		(body.FromDate > 0 && body.ToDate == 0) ||
		(body.FromDate == 0 && body.ToDate > 0) ||
		(body.FromDate > 0 && body.ToDate > 0 && body.FromDate > body.ToDate)
	if invalidDateRange {
		return body, fmt.Errorf("both from date and to date must be provided together, must be non negative, and from date must be less than or equal to to date")
	}
	if body.Size == 0 {
		body.Size = 10
	}
	// Success
	return body, nil
}

func (h *CVEHandler) verifyRejectCVEs(c echo.Context) (body model.RequestCVEsReject, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	processedIDs, err := ProcessCVEIDs(body.IDs)
	if err != nil {
		return body, err
	}
	body.IDs = processedIDs
	err = body.Filter.Verify()
	if err != nil {
		return body, err
	}
	// Success
	return body, nil
}

func (h *CVEHandler) verifyInternalFlagCVEs(c echo.Context) (body model.RequestCVEsInternalFlag, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if len(body.IDs) > 1000 {
		return body, errors.New("IDs list cannot contain more than 1000 items")
	}
	if body.Action != defs.MarkInternalFlag && body.Action != defs.DeleteInternalFlag {
		return body, errors.New("action must be 1 (MarkInternalFlag) or 2 (DeleteInternalFlag)")
	}
	if len(body.FlagsName) <= 0 {
		return body, errors.New("flag list must contain at least one flag")
	}
	flagsName := make([]string, 0)
	for _, flag := range body.FlagsName {
		trimmed := strings.TrimSpace(flag)
		if trimmed != "" {
			flagsName = append(flagsName, trimmed)
		}
	}
	body.FlagsName = flagsName
	if body.IDs, err = ProcessCVEIDs(body.IDs); err != nil {
		return body, err
	}
	err = body.Filter.Verify()
	if err != nil {
		return body, err
	}
	// Success
	return body, nil
}

func (h *CVEHandler) verifySearchInternalFlag(c echo.Context) (body model.RequestInternalFlagSearch, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.Keyword = strings.TrimSpace(body.Keyword)
	// Success
	return body, nil
}

func (h *CVEHandler) addProduct(products []*model.CPEMeta) {
	for _, c := range products {
		bts, err := json.Marshal(c)
		if err != nil {
			h.logger.Errorf("failed to marshal cpe, reason: %v", err)
			continue
		}
		if err := h.queue.Publish("", defs.QueueLogstashCPE, rabbit.Message{
			Body:        bts,
			ContentType: rabbit.MIMEApplicationJSON,
			Mode:        rabbit.Persistent,
		}); err != nil {
			h.logger.Errorf("failed to publish cpe, reason: %v", err)
			continue
		}
	}
}

func (h *CVEHandler) crawlAsset(ctx context.Context) {
	group, c := errgroup.WithContext(ctx)
	delay := clock.Minute * 5
	group.Go(func() error {
		for {
			allowRoles := make([]string, 0)
			roles, err := h.mongo.Account().Roles().FindAll(&bson.M{"permissions": defs.PermissionViewVul}, []string{})
			if err != nil {
				h.logger.Errorf("h.mongo.Roles.FindAll failed, reason: %v", err)
				if err.Error() != mg.NotFoundError {
					return err
				}
				clock.Sleep(delay)
				continue
			}
			for _, role := range roles {
				allowRoles = append(allowRoles, role.RoleID)
			}
			orgs, err := h.mongo.Account().GroupUser().FindAll(&bson.M{"role": bson.M{"$in": allowRoles}}, []string{})
			if err != nil {
				h.logger.Errorf("h.mongo.GroupUser.FindAll failed, reason: %v", err)
				if err.Error() != mg.NotFoundError {
					return err
				}
				clock.Sleep(delay)
				continue
			}
			organizations := make([]string, 0)
			for _, org := range orgs {
				if org.IsActive() {
					organizations = append(organizations, org.TenantID)
				}
			}
			h.logger.Infof("total: %d organizations", len(organizations))
			// Collect Asset
			query := map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"term": map[string]interface{}{
								"type": defs.AssetTypeProduct,
							},
						},
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
						map[string]interface{}{
							"terms": map[string]interface{}{
								"organization": organizations,
							},
						},
					},
				},
			}
			assets, err := h.elastic.Enduser().Asset().FindAll(context.Background(), query, []string{})
			if err != nil {
				h.logger.Errorf("h.elastic.Enduser.Asset.FindAll failed, reason: %v", err)
				clock.Sleep(delay)
				continue
			}
			h.logger.Infof("total: %d assets", len(assets))
			// Lock
			news := map[string][]*cpe.Item{}
			for _, asset := range assets {
				if asset.Value != "" {
					c, err := cpe.NewItemFromFormattedString(strings.ToLower(asset.Value))
					if err != nil {
						h.logger.Errorf("cpe.NewItemFromFormattedString (%s) failed, reason: %v", asset.Value, err)
						continue
					}
					if value, ok := news[asset.Organization]; ok {
						value = append(value, c)
						news[asset.Organization] = value
					} else {
						news[asset.Organization] = []*cpe.Item{c}
					}
				}
			}
			h.mutex.Lock()
			h.assets = news
			h.mutex.Unlock()
			select {
			case <-c.Done():
				return nil
			default:
				clock.Sleep(delay)
			}
		}
	})
}

func (h *CVEHandler) newPoolMultilang() *ants.PoolWithFunc {
	p, _ := ants.NewPoolWithFunc(20, func(body interface{}) {
		msg := body.(*model.CVEJobLanguage)
		defer msg.WG.Done()
		languages, err := h.elastic.Enrichment().CVELang("*").FindByID(context.Background(), msg.Results[msg.Index].ID)
		if err != nil {
			h.logger.Errorf("failed to get cve (%s) languages, reason: %v", msg.Results[msg.Index].ID, err)
			return
		}
		for _, language := range languages {
			switch language.Lang {
			case defs.LangVI:
				msg.Results[msg.Index].MultiLang.VI = language
			case defs.LangEN:
				msg.Results[msg.Index].MultiLang.EN = language
			}
		}
	})
	// Success
	return p
}

type mapChecklist struct {
	Affect    checklist
	Exploit   checklist
	Patch     checklist
	Ability   checklist
	Condition checklist
}
type checklist struct {
	Title     string       `json:"title"`
	Checklist []checkpoint `json:"checklist"`
}
type checkpoint struct {
	Point int `json:"point"`
}

func (h *CVEHandler) verifySearchFilter(body model.RequestCVESearch) (err error) {
	if body.Keyword != "" {
		body.Keyword = strings.ToLower(strings.TrimSpace(body.Keyword))
	}
	if body.Checker != "" {
		body.Checker = strings.ToLower(body.Checker)
	}
	if body.Status == nil {
		body.Status = make([]int, 0)
	}
	if body.Severity.VTI.Version == "" && len(body.Severity.VTI.Value) > 0 {
		body.Severity.VTI.Version = defs.VersionVcs10
	}
	if body.Severity.VTI.Version != "" {
		if !slice.String(defs.EnumVTIVersion).Contains(body.Severity.VTI.Version) {
			return errors.New("invalid value for param <severity.vti.version>")
		}
	}
	if body.Severity.VTI.Value == nil {
		body.Severity.VTI.Value = make([]int, 0)
	}

	if body.Severity.Global.Version == nil {
		body.Severity.Global.Version = make([]string, 0)
	}

	for _, it := range body.Severity.Global.Version {
		if it != "" {
			if !slice.String(defs.EnumGlobalVersion).Contains(it) {
				return errors.New("invalid value for param <severity.global.version>")
			}
		}
	}
	if body.Severity.Global.SeverityVersion2 == nil {
		body.Severity.Global.SeverityVersion2 = make([]int, 0)
	}
	if body.Severity.Global.SeverityVersion3 == nil {
		body.Severity.Global.SeverityVersion3 = make([]int, 0)
	}
	if len(body.Languages) > 0 {
		languages := make([]string, 0)
		for _, lang := range body.Languages {
			if !strings.Contains(lang, ",") {
				if _, ok := defs.MappingLanguage[lang]; !ok {
					return errors.New("invalid value for param <languages>")
				}
			}
			languages = append(languages, lang)
		}
		body.Languages = slice.String(languages).Unique().Extract()
	}
	if body.Time.Approved.Gte > 0 && body.Time.Approved.Lte > 0 && body.Time.Approved.Gte > body.Time.Approved.Lte {
		return errors.New("invalid value for param <time.approved.gte> greater than <time.approved.lte>")
	}
	if body.Time.Modified.Gte > 0 && body.Time.Modified.Lte > 0 && body.Time.Modified.Gte > body.Time.Modified.Lte {
		return errors.New("invalid value for param <time.modified.gte> greater than <time.modified.lte>")
	}
	if body.Time.AnalysisTime.Gte > 0 && body.Time.AnalysisTime.Lte > 0 && body.Time.AnalysisTime.Gte > body.Time.AnalysisTime.Lte {
		return errors.New("invalid value for param <time.modified.gte> greater than <time.modified.lte>")
	}
	body.Sort = make([]string, 0)
	if body.Time.Approved.Gte > 0 || body.Time.Approved.Lte > 0 {
		body.Sort = append(body.Sort, "-approved")
	}

	if body.Time.Modified.Gte > 0 || body.Time.Modified.Lte > 0 {
		body.Sort = append(body.Sort, "-modified")
	}

	if body.Time.AnalysisTime.Gte > 0 || body.Time.AnalysisTime.Lte > 0 {
		body.Sort = append(body.Sort, "-analysis_time")
	}

	if len(body.Sort) == 0 || len(body.Sort) > 1 {
		body.Sort = append(body.Sort, "-analysis_time")
	}
	if body.Size == 0 {
		body.Size = 20
	}
	// Success
	return nil
}

func (h *CVEHandler) GetGroup(tenantID string) (*model.Group, error) {
	client := resty.New()
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.SetTimeout(time.Duration(clock.Minute * clock.Duration(h.config.Api.Timeout)))
	res, err := client.R().Get(fmt.Sprintf(h.config.Api.Route.APIGroup, tenantID))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("get url (%s) error, reason: %v", fmt.Sprintf(h.config.Api.Route.APIGroup, tenantID), err))
	}
	if res.StatusCode() != rest.StatusOK {
		return nil, errors.New(fmt.Sprintf("get url (%s) return code %d", fmt.Sprintf(h.config.Api.Route.APIGroup, tenantID), res.StatusCode()))
	}
	group := model.GetGroupResponse{}
	err = json.Unmarshal(res.Body(), &group)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("marshal group error: %v", err))
	}

	return &group.Detail, nil
}

func ConvertCPEFormat(cpe string) *model.CPE {
	CPEformat := strings.Split(cpe, ":")
	return &model.CPE{
		CPEDetail: model.CPEDetail{
			Value:   cpe,
			Vendor:  CPEformat[3],
			Part:    CPEformat[2],
			Product: CPEformat[4],
			Version: CPEformat[5],
			Update:  CPEformat[6],
		},
		SwEdition: CPEformat[9],
		Edition:   CPEformat[7],
		Other:     CPEformat[12],
		Language:  CPEformat[8],
		TargetSw:  CPEformat[10],
		TargetHw:  CPEformat[11],
	}
}

func validateCVSS(cvss model.CVSSMetric) (model.CVSSMetric, error) {
	var err error
	var v2Version, v3Version, v4Version string
	if cvss.CVSS2.Version != "" {
		switch cvss.CVSS2.Version {
		case "2.0":
			v2Version = defs.VersionCvssV20
		default:
			return cvss, fmt.Errorf("invalid CVSS v2 version: %s", cvss.CVSS2.Version)
		}
	}
	if cvss.CVSS3.Version != "" {
		switch cvss.CVSS3.Version {
		case "3.0":
			v3Version = defs.VersionCvssV30
		case "3.1":
			v3Version = defs.VersionCvssV31
		default:
			return cvss, fmt.Errorf("invalid CVSS v3 version: %s", cvss.CVSS3.Version)
		}
	}
	if cvss.CVSS4.Version != "" {
		switch cvss.CVSS4.Version {
		case "4.0":
			v4Version = defs.VersionCvssV40
		default:
			return cvss, fmt.Errorf("invalid CVSS v4 version: %s", cvss.CVSS4.Version)
		}
	}
	cvss.CVSS2, err = validateCVEMetric(cvss.CVSS2, v2Version, "cvss_v2")
	if err != nil {
		return cvss, err
	}
	cvss.CVSS3, err = validateCVEMetric(cvss.CVSS3, v3Version, "cvss_v3")
	if err != nil {
		return cvss, err
	}
	cvss.CVSS4, err = validateCVEMetric(cvss.CVSS4, v4Version, "cvss_v4")
	if err != nil {
		return cvss, err
	}
	cnaVersion := strings.TrimSpace(cvss.CNA.Version)
	if cnaVersion != "" {
		var versionStd string
		switch cnaVersion {
		case "2.0":
			versionStd = defs.VersionCvssV20
		case "3.0":
			versionStd = defs.VersionCvssV30
		case "3.1":
			versionStd = defs.VersionCvssV31
		case "4.0":
			versionStd = defs.VersionCvssV40
		default:
			return cvss, fmt.Errorf("invalid CNA CVSS version: %s (supported: 2.0, 3.0, 3.1, 4.0)", cnaVersion)
		}
		cvss.CNA, err = validateCVEMetric(cvss.CNA, versionStd, "cna")
		if err != nil {
			return cvss, err
		}
	}
	return cvss, nil
}

func validateCVEMetric(
	detail model.CVEMetric,
	versionStandard,
	fieldName string,
) (model.CVEMetric, error) {
	detail.Version = strings.TrimSpace(detail.Version)
	vectorString := strings.TrimSpace(detail.VectorString)
	if detail.Version == "" && vectorString == "" && detail.Score == 0 {
		return detail, nil
	}
	if detail.Version == "" {
		return detail, fmt.Errorf("%s: must provide all fields: version", fieldName)
	}
	if vectorString != "" && !ValidateCVSSVectorString(versionStandard, vectorString) {
		return detail, fmt.Errorf("%s.vectorString does not match version %s format", fieldName, versionStandard)
	}
	if detail.Score != 0 {
		if detail.Score < 0.0 || detail.Score > 10.0 {
			return detail, fmt.Errorf("invalid value for %s.score", fieldName)
		}
		rounded := float32(math.Round(float64(detail.Score)*10) / 10)
		detail.Score = rounded
	}
	source := strings.ToUpper(detail.Source)
	if source != defs.SourceCvssNvd && source != defs.SourceCvssCna {
		return detail, fmt.Errorf("%s.source must be either 'nvd' or 'cna'", fieldName)
	}
	detail.Source = source
	return detail, nil
}

func validateEPSS(epss *model.EPSSMetric) error {
	if epss.Score != nil {
		if *epss.Score < 0.0 || *epss.Score > 1.0 {
			return fmt.Errorf("invalid score: must be between 0.0 and 1.0")
		}
		s := strings.TrimRight(fmt.Sprintf("%.10f", *epss.Score), "0")
		if len(strings.Split(s, ".")) == 2 && len(strings.Split(s, ".")[1]) > 15 {
			return fmt.Errorf("invalid score: max 15 digits after decimal point")
		}
	}
	if epss.Percentile != nil {
		if *epss.Percentile < 0.0 || *epss.Percentile > 1.0 {
			return fmt.Errorf("invalid percentile: must be between 0.0 and 1.0")
		}
		s := strings.TrimRight(fmt.Sprintf("%.10f", *epss.Percentile), "0")
		if len(strings.Split(s, ".")) == 2 && len(strings.Split(s, ".")[1]) > 15 {
			return fmt.Errorf("invalid percentile: max 15 digits after decimal point")
		}
	}
	return nil
}

func validateCWE(cweArray []model.CWEMetric) ([]model.CWEMetric, error) {
	if len(cweArray) == 0 {
		return cweArray, nil
	}
	for i, cwe := range cweArray {
		cwe.ID = strings.TrimSpace(cwe.ID)
		if cwe.ID == "" {
			return nil, fmt.Errorf("CWE ID is required for item %d", i+1)
		}
		if !regexp.MustCompile(defs.RegexCWEID).MatchString(cwe.ID) {
			return nil, fmt.Errorf("invalid CWE ID format for item %d: must be CWE-XXXX", i+1)
		}
		cwe.Name = strings.TrimSpace(cwe.Name)
		//if cwe.Name == "" {
		//	return nil, fmt.Errorf("CWE Name is required for item %d", i+1)
		//}
		cwe.Link = strings.TrimSpace(cwe.Link)
		if cwe.Link == "" {
			return nil, fmt.Errorf("link is required for item %d", i+1)
		}
		cweArray[i] = cwe
	}
	cweMap := make(map[string]bool)
	for i, cwe := range cweArray {
		if cweMap[cwe.ID] {
			return nil, fmt.Errorf("duplicate CWE ID: %s at item %d", cwe.ID, i+1)
		}
		cweMap[cwe.ID] = true
	}
	return cweArray, nil
}

func validateCVEID(id string) (string, error) {
	id = strings.ToUpper(id)
	re := regexp.MustCompile(defs.RegexCVE)
	if !re.MatchString(id) {
		return "", errors.New("invalid CVE ID format")
	}
	return id, nil
}

func validateLanguage(lang string) (string, error) {
	lang = strings.TrimSpace(lang)
	if lang == "" {
		return "", errors.New("language is required")
	}
	if _, ok := defs.MappingLanguage[lang]; !ok {
		return "", errors.New("invalid language for parameter <lang>")
	}
	return lang, nil
}

func ValidateCVSSVectorString(version, vectorString string) bool {
	version = strings.TrimSpace(version)
	vectorString = strings.TrimSpace(vectorString)
	vectorString = strings.TrimSuffix(vectorString, ":")
	pattern, exists := defs.CVSSVectorRegexMap[version]
	if !exists {
		return false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(vectorString)
}

func sliceContains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func filterTags(tags, tagsToRemove []string) []string {
	var result []string
	for _, tag := range tags {
		if !sliceContains(tagsToRemove, tag) {
			result = append(result, tag)
		}
	}
	return result
}

func ProcessCVEIDs(ids []string) ([]string, error) {
	processedIDs := make([]string, 0, len(ids))
	for _, id := range ids {
		lowerID := strings.ToLower(id)
		if strings.Contains(lowerID, "cve-") {
			processedIDs = append(processedIDs, hash.SHA1(strings.ToUpper(lowerID)))
		}
	}
	if len(processedIDs) == 0 {
		return nil, errors.New("no valid CVE IDs")
	}
	return processedIDs, nil
}

func (h *CVEHandler) FetchCVEs(body *model.RequestCVECommon) ([]*model.CVE, error) {
	var listCVE []*model.CVE
	var err error
	should := make([]interface{}, 0)
	for _, id := range body.IDs {
		should = append(should, map[string]interface{}{
			"term": map[string]interface{}{
				"id": id,
			},
		})
	}
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"should": should,
		},
	}
	if len(body.IDs) > 0 {
		listCVE, err = h.elastic.Enrichment().CVE().Find(context.Background(), query, []string{}, 0, len(body.IDs))
		return listCVE, err
	}
	if body.Filter.Time.Approved.Gte > 0 || body.Filter.Time.Approved.Lte > 0 {
		if len(body.Filter.Status) > 1 || (len(body.Filter.Status) == 1 && body.Filter.Status[0] != 2) {
			// Trả về empty slice của []*model.CVE
			return []*model.CVE{}, nil
		}
	}
	query = body.Filter.PrepareQuery()
	listCVE, err = h.elastic.Enrichment().CVE().Find(
		context.Background(),
		query,
		body.Filter.Sort,
		body.Filter.Offset,
		body.Filter.Size,
	)
	return listCVE, err
}
