package handler

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"

	"ws-lookup/adapter/elastic"
	"ws-lookup/adapter/kafka"
	"ws-lookup/adapter/resty"
	"ws-lookup/defs"
	"ws-lookup/model"
	"ws-lookup/utils"

	"github.com/labstack/echo/v4"
	"github.com/panjf2000/ants/v2"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/tld"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

type LookupHandler struct {
	name             string
	logger           pencil.Logger
	elastic          elastic.GlobalRepository
	extractor        tld.Service
	client           resty.Client
	scanChan         chan *udm.EntityJob
	producerEnrich   kafka.Producer
	producerEvaluate kafka.Producer
	config           model.Config
}

func NewLookupHandler(ctx context.Context, conf model.Config) LookupHandlerInterface {
	handler := &LookupHandler{
		name:    defs.HandlerLookup,
		elastic: elastic.NewGlobalRepository(conf.Adapter.Elastic),
		client:  resty.NewClient(conf.Adapter.Resty),
		config:  conf,
	}

	handler.logger = utils.InitializeLogger(handler.name)

	handler.extractor = utils.InitializeExtractor()

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

func (h *LookupHandler) Elastic() elastic.GlobalRepository {
	// Success
	return h.elastic
}

func (h *LookupHandler) Lookup(c echo.Context) error {
	req, err := h.verifyLookup(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	var entityDoc *udm.Entity
	var response *udm.Entity
	entityValue, entityType := req.Value, req.EntityType

	// Check if request EntityType is empty
	if len(entityType) == 0 {
		// Find by value from all UDM indices (udm-*)
		docs, err := h.Elastic().UDM().Object().FindByValue(entityValue)
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		// Get first document with valid entity type
		for _, doc := range docs {
			if _, ok := defs.EnumEntityType[doc.GetType()]; ok {
				entityDoc = doc
				break
			}
		}
		// No valid document found
		if entityDoc == nil {
			return rest.JSON(c).Code(rest.StatusNotFound).Go()
		}
		// Set entity type to found document's entity type
		entityType = entityDoc.GetType()
	} else {
		// Generate entity ID
		entityID := hash.SHA1(fmt.Sprintf("%s--%s", entityValue, entityType))
		// Find by ID from index udm-{entityType}
		entityDoc, err = h.Elastic().UDM().Object().Get(entityID, entityType)
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}

	if entityDoc == nil {
		// Initialize UDM entity
		emptyEntity := udm.NewEntity(entityValue, entityType)
		// Populate entity noun
		switch entityType {
		case udm.EntityTypeDomain:
			extracted := h.extractor.Extract("http://" + entityValue)
			emptyEntity.Noun.Domain = &udm.Domain{
				Name: entityValue,
				TLD:  extracted.TLD,
				Root: extracted.Root,
				Sub:  extracted.Sub,
			}
		case udm.EntityTypeIPAddress:
			ipType := udm.IPTypeIPv4
			if utils.IsIPv6(entityValue) {
				ipType = udm.IPTypeIPv6
			}
			emptyEntity.Noun.IP = &udm.IP{
				IP:       entityValue,
				IPNumber: utils.IPToInt(entityValue, ipType),
				Type:     ipType,
			}
		case udm.EntityTypeURL:
			extracted := h.extractor.Extract(entityValue)
			emptyEntity.Noun.URL = &udm.URL{
				Domain: extracted.FullDomain(),
				URL:    entityValue,
			}
		case udm.EntityTypeFile:
			udmFile := &udm.File{}
			switch {
			case utils.IsMD5(entityValue):
				udmFile.MD5 = entityValue
			case utils.IsSHA1(entityValue):
				udmFile.SHA1 = entityValue
			case utils.IsSHA256(entityValue):
				udmFile.SHA256 = entityValue
			case utils.IsSHA512(entityValue):
				udmFile.SHA512 = entityValue
			}
			emptyEntity.Noun.File = udmFile
		}
		if err := h.Elastic().UDM().Object().InsertOne(emptyEntity, emptyEntity.GetType()); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		// Publish scan requests
		h.scanChan <- &udm.EntityJob{
			Entity:              *emptyEntity,
			CollectedEntityType: "",
		} // Enrichment
		h.scanChan <- &udm.EntityJob{
			Entity:              *emptyEntity,
			CollectedEntityType: udm.EntityTypeSecurityResult,
		} // Evaluate
		entityDoc = emptyEntity
	}
	// Set response entity
	response = entityDoc
	response.Enrichment = &udm.Enrichment{}
	response.Evaluate = &udm.Evaluate{}

	var wgLookup sync.WaitGroup
	// Enrichment
	if slices.Contains(req.Sections, defs.SectionEnrichment) {
		wgLookup.Add(1)
		go func() {
			defer wgLookup.Done()
			var wgEnrichment sync.WaitGroup
			switch entityType {
			case udm.EntityTypeDomain:
				wgEnrichment.Add(4)
				// Popularity Ranks
				go func() {
					defer wgEnrichment.Done()
					utils.EnrichRank(h.Elastic(), response, h.scanChan, 10, 0, h.logger)
				}()
				// Domain Whois
				go func() {
					defer wgEnrichment.Done()
					utils.EnrichWhois(h.Elastic(), response, h.scanChan, 10, 0, false, h.logger)
				}()
				// Domain DNS Record
				go func() {
					defer wgEnrichment.Done()
					utils.EnrichDNSRecord(h.Elastic(), response, h.scanChan, 10, 0, h.logger)
				}()
				// SSL Certificate
				go func() {
					defer wgEnrichment.Done()
					utils.EnrichSSLCertificate(h.Elastic(), response, h.scanChan, 10, 0, true, h.logger)
				}()
			case udm.EntityTypeIPAddress:
				wgEnrichment.Add(2)
				// IP Address Artifact
				go func() {
					defer wgEnrichment.Done()
					utils.EnrichArtifact(h.Elastic(), response, h.scanChan, 10, 0, false, h.logger)
				}()
				// SSL Certificate
				go func() {
					defer wgEnrichment.Done()
					utils.EnrichSSLCertificate(h.Elastic(), response, h.scanChan, 10, 0, false, h.logger)
				}()
			case udm.EntityTypeURL:
				// URL Whois
				wgEnrichment.Add(1)
				go func() {
					defer wgEnrichment.Done()
					utils.EnrichWhois(h.Elastic(), response, h.scanChan, 10, 0, false, h.logger)
				}()
			case udm.EntityTypeFile:
				// TODO: implement
			}
			wgEnrichment.Wait()
			// Set response enrichment
		}()
	}

	// Security Result
	if slices.Contains(req.Sections, defs.SectionEvaluate) {
		wgLookup.Add(1)
		go func() {
			defer wgLookup.Done()
			utils.EnrichSecurityResult(h.Elastic(), response, h.scanChan, h.logger)
		}()
	}

	// Community
	if slices.Contains(req.Sections, defs.SectionCommunity) {
		wgLookup.Add(1)
		go func() {
			defer wgLookup.Done()
			// TODO: implement
		}()
	}

	wgLookup.Wait()
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(response).Go()
}

func (h *LookupHandler) Identify(c echo.Context) error {
	req, err := h.verifyIdentify(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Message(err.Error()).Log(err).Go()
	}

	response := make(map[string][]string)
	for category := range defs.EnumLookupType {
		response[category] = make([]string, 0)
	}

	var wgIdentify sync.WaitGroup
	var muIdentify sync.Mutex
	p, err := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgIdentify.Done()
		value := i.(string)
		category := defs.LookupTypeUnknown

		switch {
		case utils.IsDomain(value):
			category = defs.LookupTypeDomain
		case utils.IsIP(value):
			category = defs.LookupTypeIP
		case utils.IsSample(value):
			category = defs.LookupTypeHash
		case utils.IsCVE(value):
			category = defs.LookupTypeCVE
		}

		muIdentify.Lock()
		defer muIdentify.Unlock()
		response[category] = append(response[category], value)
	})
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}

	for _, value := range req.Values {
		wgIdentify.Add(1)
		if err = p.Invoke(value); err != nil {
			h.logger.Errorf("failed to invoke: %v", err)
		}
	}

	wgIdentify.Wait()

	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(response).Go()
}

func (h *LookupHandler) verifyLookup(c echo.Context) (req model.RequestLookup, err error) {
	// Bind
	if err = Validate(c, &req); err != nil {
		return req, err
	}
	// Validate Entity Type
	if len(req.EntityType) == 0 {
		req.EntityType = utils.InferEntityType(req.Value)
	} else if _, ok := defs.EnumEntityType[req.EntityType]; !ok {
		return req, errors.New(defs.ErrInvalidEntityType)
	} else {
		// Validate Value and Entity Type
		switch req.EntityType {
		case udm.EntityTypeDomain:
			req.Value = strings.TrimSuffix(req.Value, "/")
			if !utils.IsDomain(req.Value) {
				return req, errors.New(defs.ErrInvalidValueDomain)
			}
		case udm.EntityTypeURL:
			if !utils.IsURL(req.Value) {
				return req, errors.New(defs.ErrInvalidValueURL)
			}
			req.Value = strings.TrimSuffix(req.Value, "/")
		case udm.EntityTypeIPAddress:
			if !utils.IsIP(req.Value) {
				return req, errors.New(defs.ErrInvalidValueIP)
			}
		case udm.EntityTypeFile:
			if !utils.IsSample(req.Value) {
				return req, errors.New(defs.ErrInvalidValueFile)
			}
		}
	}
	// Validate Sections
	if req.Sections == nil || len(req.Sections) == 0 {
		req.Sections = []string{defs.SectionEnrichment, defs.SectionEvaluate, defs.SectionCommunity}
	} else {
		for _, section := range req.Sections {
			if _, ok := defs.EnumSection[section]; !ok {
				return req, fmt.Errorf(defs.ErrInvalidSection, section)
			}
		}
	}
	// Success
	return req, nil
}

func (h *LookupHandler) verifyIdentify(c echo.Context) (req model.RequestIdentify, err error) {
	// Bind
	if err = Validate(c, &req); err != nil {
		return req, err
	}
	// Validate
	if len(req.Values) > defs.DefaultMaxIdentifyLimit {
		return req, errors.New(defs.ErrTooManyObjects)
	}
	// Success
	return req, nil
}
