package handler

import (
	"context"
	"errors"
	"sort"
	"strings"

	"ws-lookup/adapter/elastic"
	"ws-lookup/defs"
	"ws-lookup/model"
	"ws-lookup/utils"

	"github.com/labstack/echo/v4"
	es "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
)

type CVEHandler struct {
	name    string
	context context.Context
	logger  pencil.Logger
	elastic elastic.GlobalRepository
	config  model.Config
}

func NewCVEHandler(ctx context.Context, conf model.Config) CVEHandlerInterface {
	handler := &CVEHandler{name: defs.HandlerCVE, context: ctx, config: conf}
	handler.logger = utils.InitializeLogger(handler.name)
	handler.elastic = elastic.NewGlobalRepository(conf.Adapter.Elastic)
	// Success
	return handler
}

func (h *CVEHandler) Elastic() elastic.GlobalRepository {
	// Success
	return h.elastic
}

func (h *CVEHandler) LookupMultiple(c echo.Context) error {
	// Validate request
	req, err := h.verifyLookupMultiple(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Message(err.Error()).Log(err).Go()
	}
	data := make([]*model.LookupMultipleItemCVE, 0)
	failed := make([]*model.LookupMultipleItemCVE, 0)
	for _, cve := range req.Invalid {
		failed = append(failed, &model.LookupMultipleItemCVE{
			Value: cve,
			Error: defs.ErrInvalidValueCVE,
		})
	}
	documents, err := h.elastic.Enrichment().CVE().FindByValues(req.Values)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		documents = make([]*model.CVE, 0)
	}
	foundCVEs := make([]string, 0)
	for _, doc := range documents {
		foundCVEs = append(foundCVEs, doc.Name)
		data = append(data, &model.LookupMultipleItemCVE{
			Value:     doc.Name,
			Created:   doc.Created,
			Published: doc.Published,
			Approved:  doc.Approved,
			Products:  doc.GetProducts(),
			Score:     &doc.Score,
		})
	}
	for _, cve := range req.Values {
		if !slice.String(foundCVEs).Contains(cve) {
			failed = append(failed, &model.LookupMultipleItemCVE{Value: cve, Error: defs.ErrCVENotFound})
		}
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(&model.ResponseLookupMultipleCVE{Data: data, Failed: failed}).Go()
}

func (h *CVEHandler) verifyLookupMultiple(c echo.Context) (req model.RequestLookupMultiple, err error) {
	// Bind
	if err = Validate(c, &req); err != nil {
		return req, err
	}
	// Validate
	if len(req.Values) > defs.DefaultMaxLookupMultipleLimit {
		return req, errors.New(defs.ErrTooManyObjects)
	}
	// Preprocessing
	for i := range req.Values {
		req.Values[i] = strings.TrimSpace(strings.ToUpper(req.Values[i]))
	}
	req.Values = slice.String(req.Values).Unique().Extract()
	sort.Strings(req.Values)
	// Filter domains
	validCVE := make([]string, 0)
	req.Invalid = make([]string, 0)
	for _, value := range req.Values {
		if !utils.IsCVE(value) {
			req.Invalid = append(req.Invalid, value)
		} else {
			validCVE = append(validCVE, value)
		}
	}
	req.Values = validCVE
	// Success
	return req, nil
}
