package handler

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/go-resty/resty/v2"
	es "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/core/cpe"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type CPEHandler struct {
	name    string
	logger  pencil.Logger
	elastic elastic.GlobalRepository
	config  model.Config
}

func NewCPEHandler(conf model.Config) CPEHandlerInterface {
	handler := &CPEHandler{name: defs.HandlerCpe, config: conf}
	handler.logger, _ = pencil.New(handler.name, pencil.DebugLevel, true, os.Stdout)
	handler.elastic = elastic.NewGlobalRepository(handler.config.Connector.Elastic)
	if handler.config.Api.Timeout == 0 {
		handler.config.Api.Timeout = defs.DefaultTimeout
	}
	// Success
	return handler
}

func (h *CPEHandler) Config(c echo.Context) error {
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{
		"part": defs.MappingProductType,
	}).Go()
}

func (h *CPEHandler) SuggestVendor(c echo.Context) error {
	body, err := h.verifySuggestVendor(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	documents, err := h.elastic.Enrichment().CPE().FindCollapse(
		context.Background(),
		body.PrepareQuery(),
		[]string{fmt.Sprintf("+%s", defs.KeyVendor)},
		defs.KeyVendor,
		body.Offset,
		body.Size,
	)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusOK).Body(make([]string, 0)).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	results := make([]string, 0)
	for _, document := range documents {
		results = append(results, document.Vendor)
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(results).Go()
}

func (h *CPEHandler) SuggestProduct(c echo.Context) error {
	body, err := h.verifySuggestProduct(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	documents, err := h.elastic.Enrichment().CPE().FindCollapse(
		context.Background(),
		body.PrepareQuery(),
		[]string{fmt.Sprintf("+%s", defs.KeyProduct)},
		defs.KeyProduct,
		body.Offset,
		body.Size,
	)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusOK).Body(make([]string, 0)).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	results := make([]string, 0)
	for _, document := range documents {
		results = append(results, document.Product)
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(results).Go()
}

func (h *CPEHandler) SuggestVersion(c echo.Context) error {
	body, err := h.verifySuggestVersion(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	documents, err := h.elastic.Enrichment().CPE().FindCollapse(
		context.Background(),
		body.PrepareQuery(),
		[]string{fmt.Sprintf("+%s", defs.KeyVersion)},
		defs.KeyVersion,
		body.Offset,
		body.Size,
	)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusOK).Body(make([]string, 0)).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	results := make([]string, 0)
	for _, document := range documents {
		results = append(results, document.Version)
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(results).Go()
}

func (h *CPEHandler) SuggestUpdate(c echo.Context) error {
	body, err := h.verifySuggestUpdate(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	documents, err := h.elastic.Enrichment().CPE().FindCollapse(
		context.Background(),
		body.PrepareQuery(),
		[]string{fmt.Sprintf("+%s", defs.KeyUpdate)},
		defs.KeyUpdate,
		body.Offset,
		body.Size,
	)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusOK).Body(make([]string, 0)).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	results := make([]string, 0)
	for _, document := range documents {
		results = append(results, document.Update)
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(results).Go()
}

func (h *CPEHandler) Statistic(c echo.Context) error {
	body, err := h.verifyStatistic(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	filterCreator := make([]interface{}, 0)
	if body.Creator != "" {
		filterCreator = append(filterCreator, map[string]interface{}{
			"term": map[string]interface{}{
				"creator": body.Creator,
			},
		})
	}
	query := defs.ElasticsearchQueryFilterMatchAll
	if len(filterCreator) > 0 {
		query = map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filterCreator,
			},
		}
	}
	common, err := h.elastic.Enrichment().CPE().AggregationCount(context.Background(), query, []string{"part", "creator"})
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	results := map[string]interface{}{}
	// Creator
	creators := make([]es.ResultAggregationCount, 0)
	for _, creator := range common["creator"] {
		if creator.Value != "Unknown" && creator.Value != "" {
			creators = append(creators, creator)
		}
	}
	results["creator"] = creators
	// Part
	results["part"] = common["part"]
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(results).Go()
}

func (h *CPEHandler) Search(c echo.Context) error {
	body, err := h.verifySearch(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.PrepareQuery()
	documents := make([]*model.CPE, 0)
	if body.Size != -1 {
		documents, err = h.elastic.Enrichment().CPE().Find(context.Background(), query, body.Sort, body.Offset, body.Size)
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
		}
	} else {
		documents, err = h.elastic.Enrichment().CPE().FindAll(context.Background(), query, body.Sort)
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
		}
	}
	results := make([]*model.CPEDetail, 0)
	for _, document := range documents {
		result := &document.CPEDetail
		// Vendor
		document.Vendor = strings.ReplaceAll(document.Vendor, "-", "_")
		vendorPath := strings.Split(document.Vendor, "_")
		vendorVerbose := make([]string, 0)
		for _, v := range vendorPath {
			vendorVerbose = append(vendorVerbose, strings.Title(strings.ToLower(v)))
		}
		result.Vendor = strings.Join(vendorVerbose, " ")
		// Product
		document.Product = strings.ReplaceAll(document.Product, "-", "_")
		productPath := strings.Split(document.Product, "_")
		productVerbose := make([]string, 0)
		for _, v := range productPath {
			productVerbose = append(productVerbose, strings.Title(strings.ToLower(v)))
		}
		result.Product = strings.Join(productVerbose, " ")
		results = append(results, result)
	}
	count, err := h.elastic.Enrichment().CPE().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}

	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results, "total": count}).Go()
}

func (h *CPEHandler) Exist(c echo.Context) error {
	body, err := h.verifyCreate(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	value, err := h.generate(body.Vendor, body.Part, body.Product, body.Version, body.Update)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	document := &model.CPE{}
	document.Apply(*value)
	if _, err = h.elastic.Enrichment().CPE().GetByID(context.Background(), document.ID); err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		// Success
		return rest.JSON(c).Code(rest.StatusOK).Go()
	} else {
		return rest.JSON(c).Code(rest.StatusConflict).Go()
	}
}

func (h *CPEHandler) Create(c echo.Context) error {
	body, err := h.verifyCreate(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	editor := c.Get("user_name").(string)
	versions := strings.Split(body.Version, ";")
	for _, version := range versions {
		value, err := h.generate(body.Vendor, body.Part, body.Product, version, body.Update)
		if err != nil {
			return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
		}
		now, _ := clock.Now(clock.Local)
		document := &model.CPE{
			CPEDetail: model.CPEDetail{
				Created: clock.UnixMilli(now),
				Creator: editor,
			},
		}
		document.Apply(*value)
		if _, err = h.elastic.Enrichment().CPE().GetByID(context.Background(), document.ID); err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			if err = h.elastic.Enrichment().CPE().Store(context.Background(), document); err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Go()
}

func (h *CPEHandler) Delete(c echo.Context) error {
	body, err := h.verifyIDs(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	for _, id := range body.IDs {
		if err = h.elastic.Enrichment().CPE().DeleteByID(context.Background(), id); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(len(body.IDs)).Go()
}

func (h *CPEHandler) SearchVendor(c echo.Context) error {
	body, err := h.verifySuggestVendor(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.PrepareQuery()
	documents, err := h.elastic.Enrichment().CPE().Find(
		context.Background(),
		query,
		[]string{
			fmt.Sprintf("+%s", defs.KeyVendor),
			fmt.Sprintf("+%s", defs.KeyProduct),
			fmt.Sprintf("+%s", defs.KeyVersion),
			fmt.Sprintf("+%s", defs.KeyUpdate),
		},
		body.Offset,
		body.Size,
	)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	results := make([]*model.CPEDetail, 0)
	for _, document := range documents {
		results = append(results, &document.CPEDetail)
	}
	// Count
	count, err := h.elastic.Enrichment().CPE().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results, "total": count}).Go()
}

func (h *CPEHandler) SearchProduct(c echo.Context) error {
	body, err := h.verifySuggestProduct(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.PrepareQuery()
	documents, err := h.elastic.Enrichment().CPE().Find(
		context.Background(),
		query,
		[]string{
			fmt.Sprintf("+%s", defs.KeyVendor),
			fmt.Sprintf("+%s", defs.KeyProduct),
			fmt.Sprintf("+%s", defs.KeyVersion),
			fmt.Sprintf("+%s", defs.KeyUpdate),
		},
		body.Offset,
		body.Size,
	)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	results := make([]*model.CPEDetail, 0)
	for _, document := range documents {
		results = append(results, &document.CPEDetail)
	}
	// Count
	count, err := h.elastic.Enrichment().CPE().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results, "total": count}).Go()
}

func (h *CPEHandler) SearchVersion(c echo.Context) error {
	body, err := h.verifySuggestVersion(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.PrepareQuery()
	documents, err := h.elastic.Enrichment().CPE().Find(
		context.Background(),
		query,
		[]string{
			fmt.Sprintf("+%s", defs.KeyVendor),
			fmt.Sprintf("+%s", defs.KeyProduct),
			fmt.Sprintf("+%s", defs.KeyVersion),
			fmt.Sprintf("+%s", defs.KeyUpdate),
		},
		body.Offset,
		body.Size,
	)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	results := make([]*model.CPEDetail, 0)
	for _, document := range documents {
		results = append(results, &document.CPEDetail)
	}
	// Count
	count, err := h.elastic.Enrichment().CPE().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results, "total": count}).Go()
}

func (h *CPEHandler) SearchUpdate(c echo.Context) error {
	body, err := h.verifySuggestUpdate(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.PrepareQuery()
	documents, err := h.elastic.Enrichment().CPE().Find(
		context.Background(),
		query,
		[]string{
			fmt.Sprintf("+%s", defs.KeyVendor),
			fmt.Sprintf("+%s", defs.KeyProduct),
			fmt.Sprintf("+%s", defs.KeyVersion),
			fmt.Sprintf("+%s", defs.KeyUpdate),
		},
		body.Offset,
		body.Size,
	)
	if err != nil {
		if err.Error() == es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	results := make([]*model.CPEDetail, 0)
	for _, document := range documents {
		results = append(results, &document.CPEDetail)
	}
	// Count
	count, err := h.elastic.Enrichment().CPE().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results, "total": count}).Go()
}

func (h *CPEHandler) StatisticPopular(c echo.Context) error {
	body, err := h.verifyStatistic(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	filterCreator := make([]interface{}, 0)
	if body.Creator != "" {
		filterCreator = append(filterCreator, map[string]interface{}{
			"term": map[string]interface{}{
				"creator": body.Creator,
			},
		})
	}
	query := defs.ElasticsearchQueryFilterMatchAll
	if len(filterCreator) > 0 {
		query = map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filterCreator,
			},
		}
	}
	common, err := h.elastic.Enrichment().CPEPopular().AggregationCount(context.Background(), query, []string{"part", "creator"})
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	results := map[string]interface{}{}
	// Creator
	creators := make([]es.ResultAggregationCount, 0)
	for _, creator := range common["creator"] {
		if creator.Value != "Unknown" && creator.Value != "" {
			creators = append(creators, creator)
		}
	}
	results["creator"] = creators
	// Part
	results["part"] = common["part"]
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(results).Go()
}

func (h *CPEHandler) SearchPopular(c echo.Context) error {
	body, err := h.verifySearch(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.PrepareQuery()
	documents := make([]*model.CPEPopular, 0)
	if body.Size != -1 {
		documents, err = h.elastic.Enrichment().CPEPopular().Find(context.Background(), query, body.Sort, body.Offset, body.Size)
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
		}
	} else {
		documents, err = h.elastic.Enrichment().CPEPopular().FindAll(context.Background(), query, body.Sort)
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
		}
	}
	for _, document := range documents {
		// Vendor
		document.Vendor = strings.ReplaceAll(document.Vendor, "-", "_")
		vendorPath := strings.Split(document.Vendor, "_")
		vendorVerbose := make([]string, 0)
		for _, v := range vendorPath {
			vendorVerbose = append(vendorVerbose, strings.Title(strings.ToLower(v)))
		}
		document.Vendor = strings.Join(vendorVerbose, " ")
		// Product
		document.Product = strings.ReplaceAll(document.Product, "-", "_")
		productPath := strings.Split(document.Product, "_")
		productVerbose := make([]string, 0)
		for _, v := range productPath {
			productVerbose = append(productVerbose, strings.Title(strings.ToLower(v)))
		}
		document.Product = strings.Join(productVerbose, " ")
	}
	count, err := h.elastic.Enrichment().CPEPopular().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": documents, "total": count}).Go()
}

func (h *CPEHandler) CreatePopular(c echo.Context) error {
	body, err := h.verifyCreatePopular(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	result, err := h.elastic.Enrichment().CPE().Find(context.Background(), body.PrepareQuery(), []string{"-created"}, 0, 1)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusNotFound).Log(err).Go()
	}
	if len(result) == 0 {
		return rest.JSON(c).Code(rest.StatusNotFound).Log(err).Go()
	}
	document := result[0]
	if body.Product == "*" {
		document.Product = "*"
	}
	now, _ := clock.Now(clock.Local)
	popular := &model.CPEPopular{
		Created: clock.UnixMilli(now),
		Value:   "",
		Vendor:  body.Vendor,
		Part:    body.Part,
		Product: body.Product,
		Creator: c.Get("user_name").(string),
		Active:  true,
	}
	pro := cpe.NewItem()
	_ = pro.SetVendor(cpe.NewStringAttr(document.Vendor))
	_ = pro.SetPart(defs.MappingCPEPart[document.Part])
	_ = pro.SetProduct(cpe.NewStringAttr(document.Product))
	popular.Value = pro.Formatted()
	popular.GenID()
	if _, err = h.elastic.Enrichment().CPEPopular().GetByID(context.Background(), popular.ID); err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	} else {
		return rest.JSON(c).Code(rest.StatusConflict).Go()
	}
	// Store
	if err = h.elastic.Enrichment().CPEPopular().Store(context.Background(), popular); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Synchronize
	// go h.synchronize(popular.Creator)
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(popular.ID).Go()
}

func (h *CPEHandler) DeletePopular(c echo.Context) error {
	body, err := h.verifyIDs(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	for _, id := range body.IDs {
		if err = h.elastic.Enrichment().CPEPopular().DeleteByID(context.Background(), id); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	// Synchronize
	// go h.synchronize(c.Get("user_name").(string))
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(len(body.IDs)).Go()
}

func (h *CPEHandler) synchronize(creator string) {
	client := resty.New()
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.SetTimeout(time.Duration(clock.Duration(h.config.Api.Timeout) * clock.Minute))
	res, err := client.R().
		SetQueryParam("creator", creator).
		Get(fmt.Sprintf(defs.UriCustomerProductSynchronize, h.config.Api.Route.Customer))
	if err != nil {
		h.logger.Errorf("failed to synchronize, reason: %v", err)
		return
	}
	if res.StatusCode() != rest.StatusOK {
		h.logger.Errorf("failed to synchronize, status code: %d", res.StatusCode())
		return
	}
}

func (h *CPEHandler) verifySearch(c echo.Context) (body model.RequestCPESearch, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if body.Keyword != "" {
		body.Keyword = strings.ToLower(body.Keyword)
		keywords := make([]string, 0)
		for _, kw := range strings.Fields(body.Keyword) {
			keywords = append(keywords, regexp.QuoteMeta(kw))
		}
		body.Keyword = strings.Join(keywords, "*")
	}
	if len(body.Part) > 0 {
		parts := make([]string, 0)
		for _, part := range body.Part {
			part = strings.ToLower(part)
			parts = append(parts, part)
			if !slice.String(defs.EnumCpePart).Contains(part) {
				return body, errors.New("invalid value for parameter <part>")
			}
		}
		body.Part = parts
	}
	if len(body.Sort) == 0 {
		body.Sort = []string{"-created", "+value"}
	}
	if body.Size == 0 {
		body.Size = 20
	}
	// Success
	return body, nil
}

func (h *CPEHandler) verifyCreate(c echo.Context) (body model.RequestCPECreate, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.Vendor = h.encode(body.Vendor)
	if _, ok := defs.MappingProductType[body.Part]; !ok {
		return body, errors.New("invalid value for parameter <part>")
	}
	body.Product = h.encode(body.Product)
	vers := strings.Split(body.Version, ";")
	versions := make([]string, 0)
	for _, version := range vers {
		items := strings.Split(version, ",")
		for _, item := range items {
			item = h.encode(item)
			item = strings.TrimSpace(item)
			if item != "" {
				versions = append(versions, item)
			}
		}
	}
	body.Version = strings.Join(versions, ";")
	body.Update = h.encode(body.Update)
	// Success
	return body, nil
}

func (h *CPEHandler) verifyCreatePopular(c echo.Context) (body model.RequestCPEPopularCreate, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Vendor
	body.Vendor = strings.ToLower(body.Vendor)
	vendorSplit := make([]string, 0)
	for _, kw := range strings.Fields(body.Vendor) {
		vendorSplit = append(vendorSplit, regexp.QuoteMeta(kw))
	}
	body.Vendor = strings.Join(vendorSplit, "*")
	// Part
	if body.Part != "" {
		body.Part = strings.ToLower(body.Part)
		if !slice.String(defs.EnumCpePart).Contains(body.Part) {
			return body, errors.New("invalid value for parameter <part>")
		}
	}
	// Product
	body.Product = strings.ToLower(body.Product)
	productSplit := make([]string, 0)
	for _, kw := range strings.Fields(body.Product) {
		productSplit = append(productSplit, regexp.QuoteMeta(kw))
	}
	body.Product = strings.Join(productSplit, "*")
	if body.Product == "" {
		body.Product = "*"
	}
	// Success
	return body, nil
}

func (h *CPEHandler) verifyIDs(c echo.Context) (body model.RequestCPEIDs, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	results := make([]string, 0)
	for _, id := range body.IDs {
		results = append(results, strings.ToLower(strings.TrimSpace(id)))
	}
	body.IDs = results
	// Success
	return body, nil
}

func (h *CPEHandler) verifySuggestVendor(c echo.Context) (body model.RequestCPESuggestVendor, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if body.Query != "" {
		body.Query = strings.TrimSpace(body.Query)
		body.Query = strings.ToLower(body.Query)
	}
	if body.Size == 0 {
		body.Size = 20
	}
	// Success
	return body, nil
}

func (h *CPEHandler) verifySuggestProduct(c echo.Context) (body model.RequestCPESuggestProduct, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if body.Query != "" {
		body.Query = strings.TrimSpace(body.Query)
		body.Query = strings.ToLower(body.Query)
	}
	body.Vendor = strings.ToLower(body.Vendor)
	body.Vendor = strings.ReplaceAll(body.Vendor, " ", "")
	if body.Part != "" {
		body.Part = strings.ToLower(body.Part)
		if _, ok := defs.MappingProductType[body.Part]; !ok {
			return body, errors.New("invalid value for parameter <part>")
		}
	}
	if body.Size == 0 {
		body.Size = 20
	}
	// Success
	return body, nil
}

func (h *CPEHandler) verifySuggestVersion(c echo.Context) (body model.RequestCPESuggestVersion, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if body.Query != "" {
		body.Query = strings.TrimSpace(body.Query)
		body.Query = strings.ToLower(body.Query)
	}
	body.Vendor = strings.ToLower(body.Vendor)
	if body.Part != "" {
		body.Part = strings.ToLower(body.Part)
		if !slice.String(defs.EnumCpePart).Contains(body.Part) {
			return body, errors.New("invalid value for parameter <part>")
		}
	}
	body.Product = strings.ToLower(body.Product)
	if body.Size == 0 {
		body.Size = 20
	}
	// Success
	return body, nil
}

func (h *CPEHandler) verifySuggestUpdate(c echo.Context) (body model.RequestCPESuggestUpdate, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if body.Query != "" {
		body.Query = strings.TrimSpace(body.Query)
		body.Query = strings.ToLower(body.Query)
	}
	body.Vendor = strings.ToLower(body.Vendor)
	if body.Part != "" {
		body.Part = strings.ToLower(body.Part)
		if !slice.String(defs.EnumCpePart).Contains(body.Part) {
			return body, errors.New("invalid value for parameter <part>")
		}
	}
	body.Product = strings.ToLower(body.Product)
	body.Version = strings.ToLower(body.Version)
	if body.Size == 0 {
		body.Size = 20
	}
	// Success
	return body, nil
}

func (h *CPEHandler) verifyStatistic(c echo.Context) (body model.RequestCPEStatistic, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if body.Creator != "" {
		body.Creator = strings.ToLower(body.Creator)
	}
	// Success
	return body, nil
}

func (h *CPEHandler) encode(str string) string {
	str = strings.TrimSpace(str)
	str = strings.ToLower(str)
	str = strings.ReplaceAll(str, " ", "_")
	// Success
	return str
}

func (h *CPEHandler) generate(vendor, part, product, version, update string) (*cpe.Item, error) {
	value := cpe.NewItem()
	// Vendor
	if err := value.SetVendor(cpe.NewStringAttr(vendor)); err != nil {
		return nil, err
	}
	// Part
	switch part {
	case defs.ProductTypeCodeApplication:
		_ = value.SetPart(cpe.Application)
	case defs.ProductTypeCodeOperation:
		_ = value.SetPart(cpe.OperationSystem)
	case defs.ProductTypeCodeHardware:
		_ = value.SetPart(cpe.Hardware)
	default:
		_ = value.SetPart(cpe.PartNotSet)
	}
	// Product
	if err := value.SetProduct(cpe.NewStringAttr(product)); err != nil {
		return nil, err
	}
	// Version
	switch version {
	case cpe.Any.String(), "":
		_ = value.SetVersion(cpe.Any)
	case cpe.Na.String():
		_ = value.SetVersion(cpe.Na)
	default:
		if err := value.SetVersion(cpe.NewStringAttr(version)); err != nil {
			return nil, err
		}
	}
	// Update
	switch update {
	case cpe.Any.String(), "":
		_ = value.SetUpdate(cpe.Any)
	case cpe.Na.String():
		_ = value.SetUpdate(cpe.Na)
	default:
		if err := value.SetUpdate(cpe.NewStringAttr(update)); err != nil {
			return nil, err
		}
	}
	// Other
	_ = value.SetEdition(cpe.Any)
	_ = value.SetLanguage(cpe.Any)
	_ = value.SetSwEdition(cpe.Any)
	_ = value.SetTargetSw(cpe.Any)
	_ = value.SetTargetHw(cpe.Any)
	_ = value.SetOther(cpe.Any)
	// Success
	return value, nil
}
