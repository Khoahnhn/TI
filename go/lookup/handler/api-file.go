package handler

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"ws-lookup/adapter/elastic"
	"ws-lookup/adapter/kafka"
	"ws-lookup/defs"
	"ws-lookup/model"
	"ws-lookup/utils"

	"github.com/labstack/echo/v4"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

type FileHandler struct {
	name             string
	logger           pencil.Logger
	elastic          elastic.GlobalRepository
	scanChan         chan *udm.EntityJob
	producerEnrich   kafka.Producer
	producerEvaluate kafka.Producer
	config           model.Config
}

func NewFileHandler(ctx context.Context, conf model.Config) FileHandlerInterface {
	handler := &FileHandler{
		name:    defs.HandlerFile,
		elastic: elastic.NewGlobalRepository(conf.Adapter.Elastic),
		config:  conf,
	}
	handler.logger = utils.InitializeLogger(handler.name)
	handler.producerEnrich, handler.producerEvaluate = utils.InitializeProducers(ctx, &conf)
	handler.scanChan = make(chan *udm.EntityJob, runtime.NumCPU())
	go utils.HandleScanRequests(handler.scanChan, handler.producerEnrich, handler.producerEvaluate, handler.config.Adapter.Kafka.Topics, handler.logger)
	go func() {
		<-ctx.Done()
		close(handler.scanChan)
	}()
	// Success
	return handler
}

func (h *FileHandler) Elastic() elastic.GlobalRepository {
	// Success
	return h.elastic
}

func (h *FileHandler) Lookup(c echo.Context) error {
	// Validate request
	req, err := h.verifyLookup(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Message(err.Error()).Log(err).Go()
	}
	// Initialize variables
	entityValue := req.Value
	// Set response entity
	entity, err := utils.InitializeEntity(h.Elastic(), entityValue, udm.EntityTypeFile, nil, h.scanChan)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}

	entity.Enrichment = &udm.Enrichment{}
	entity.Evaluate = &udm.Evaluate{}

	var wgData sync.WaitGroup
	for sct, attrs := range req.Sections {
		wgData.Add(1)
		go func(section string, limit int, offset int, flat bool) {
			defer wgData.Done()
			switch section {
			case defs.SectionSecurityResult:
				utils.EnrichSecurityResult(h.Elastic(), entity, h.scanChan, h.logger)
			}
		}(sct, attrs.Limit, attrs.Offset, attrs.Flat)
	}
	wgData.Wait()
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(entity).Go()
}

func (h *FileHandler) verifyLookup(c echo.Context) (req model.RequestLookupSingle, err error) {
	// Bind
	if err = Validate(c, &req); err != nil {
		return req, err
	}
	req.Value = strings.ToLower(strings.TrimSpace(req.Value))
	if !utils.IsSample(req.Value) {
		return req, errors.New(defs.ErrInvalidValueFile)
	}
	// Validate Sections
	if len(req.Sections) > 0 {
		for section, attrs := range req.Sections {
			if _, ok := defs.EnumSectionFile[section]; !ok {
				return req, fmt.Errorf(defs.ErrInvalidSection, section)
			}
			attrs.Limit = min(attrs.Limit, defs.DefaultMaxLimit)
		}
	} else {
		sections := make(map[string]*model.RequestSection)
		for section := range defs.EnumSectionFile {
			sections[section] = &model.RequestSection{}
		}
		req.Sections = sections
	}
	// Success
	return req, nil
}
