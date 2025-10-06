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
	"ws-lookup/adapter/resty"
	"ws-lookup/defs"
	"ws-lookup/model"
	"ws-lookup/utils"

	"github.com/labstack/echo/v4"
	"github.com/panjf2000/ants/v2"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/tld"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

type URLHandler struct {
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

func NewURLHandler(ctx context.Context, conf model.Config) URLHandlerInterface {
	handler := &URLHandler{
		name:    defs.HandlerURL,
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

func (h *URLHandler) Elastic() elastic.GlobalRepository {
	// Success
	return h.elastic
}

func (h *URLHandler) Lookup(c echo.Context) error {
	// Validate request
	req, err := h.verifyLookup(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Message(err.Error()).Log(err).Go()
	}
	// Initialize variables
	entityValue := req.Value
	// Set response entity
	entity, err := utils.InitializeEntity(h.Elastic(), entityValue, udm.EntityTypeURL, h.extractor, h.scanChan)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}

	entity.Enrichment = &udm.Enrichment{
		HTTPRequest:      &udm.ResponseEnrichmentHTTPRequest{},
		Whois:            &udm.ResponseEnrichmentWhois{},
		PassiveDNSDomain: &udm.ResponseEnrichmentPassiveDNSDomain{},
		Subdomain:        &udm.ResponseEnrichmentSubdomain{},
		SiblingDomain:    &udm.ResponseEnrichmentSiblingDomain{},
		SSLCertificate:   &udm.ResponseEnrichmentSSLCertificate{},
	}
	entity.Evaluate = &udm.Evaluate{}

	var wgData sync.WaitGroup
	for sct, attrs := range req.Sections {
		wgData.Add(1)
		go func(section string, limit int, offset int, flat bool) {
			defer wgData.Done()
			switch section {
			case defs.SectionHTTPRequest:
				utils.EnrichHTTPRequest(h.Elastic(), entity, h.scanChan, limit, offset, flat, h.logger)
			case defs.SectionWhois:
				utils.EnrichWhois(h.Elastic(), entity, h.scanChan, limit, offset, flat, h.logger)
			case defs.SectionPassiveDNS:
				h.enrichPassiveDNS(entity, limit, offset)
			case defs.SectionSubdomains:
				h.enrichSubdomains(entity, limit, offset)
			case defs.SectionSiblings:
				h.enrichSiblings(entity, limit, offset)
			case defs.SectionSSLCertificate:
				utils.EnrichSSLCertificate(h.Elastic(), entity, h.scanChan, limit, offset, flat, h.logger)
			case defs.SectionSecurityResult:
				utils.EnrichSecurityResult(h.Elastic(), entity, h.scanChan, h.logger)
			}
		}(sct, attrs.Limit, attrs.Offset, attrs.Flat)
	}
	wgData.Wait()
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(entity).Go()
}

func (h *URLHandler) verifyLookup(c echo.Context) (req model.RequestLookupSingle, err error) {
	// Bind
	if err = Validate(c, &req); err != nil {
		return req, err
	}
	// Validate
	req.Value = strings.ToLower(strings.TrimSuffix(req.Value, "/"))
	if !utils.IsURL(req.Value) {
		return req, errors.New(defs.ErrInvalidValueURL)
	}
	// Validate Sections
	if len(req.Sections) > 0 {
		for section, attrs := range req.Sections {
			if _, ok := defs.EnumSectionURL[section]; !ok {
				return req, fmt.Errorf(defs.ErrInvalidSection, section)
			}
			attrs.Limit = min(attrs.Limit, defs.DefaultMaxLimit)
		}
	} else {
		sections := make(map[string]*model.RequestSection)
		for section := range defs.EnumSectionURL {
			sections[section] = &model.RequestSection{}
		}
		req.Sections = sections
	}
	// Success
	return req, nil
}

func (h *URLHandler) enrichPassiveDNS(entity *udm.Entity, limit int, offset int) {
	extracted := h.extractor.Extract(entity.GetValue())
	domain := extracted.FullDomain()
	if domain == "" {
		h.logger.Errorf("invalid domain for url (%s)", domain)
		return
	}
	var responsePassiveDNS model.ResponseEnrichmentPassiveDNSDomain
	res, err := h.client.GetDomainPassiveDNS(h.config.API.APIEnrichment, domain, limit, offset, &responsePassiveDNS)
	if err != nil {
		h.logger.Errorf("failed to get passive dns for %s: %v", domain, err)
		return
	}
	if res.StatusCode() >= rest.StatusBadRequest {
		h.logger.Errorf("failed to get passive dns for %s: status code %d", domain, res.StatusCode())
		return
	}

	entity.Enrichment.PassiveDNSDomain = responsePassiveDNS.Detail
	h.scanChan <- &udm.EntityJob{
		Entity:              *entity,
		CollectedEntityType: udm.EntityType("passive_dns"),
	}
	// No records found
	if responsePassiveDNS.Detail.Total == 0 {
		return
	}

	// Get unique IP from passive DNS records
	uniqueIP := make([]string, 0) // Required since concurrent map read/write not allowed
	uniqueIPMap := make(map[string]*udm.Entity)
	for _, data := range responsePassiveDNS.Detail.Data {
		ipAddress := data.IPAddress
		if _, ok := uniqueIPMap[ipAddress]; !ok {
			uniqueIP = append(uniqueIP, ipAddress)
			uniqueIPMap[ipAddress] = &udm.Entity{}
		}
	}

	// Populate artifact and security result for each unique IP entity
	var wgUnique sync.WaitGroup
	var muUnique sync.Mutex
	pUnique, err := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgUnique.Done()
		ip := i.(string)
		ipEntity, err := utils.InitializeEntity(h.Elastic(), ip, udm.EntityTypeIPAddress, h.extractor, h.scanChan)
		if err != nil {
			h.logger.Errorf("failed to get ip entity %s: %v", ip, err)
			return
		}

		var wgEnrich sync.WaitGroup
		wgEnrich.Add(2)
		go func() {
			defer wgEnrich.Done()
			utils.EnrichArtifact(h.Elastic(), ipEntity, h.scanChan, 1, 0, false, h.logger)
		}()
		go func() {
			defer wgEnrich.Done()
			utils.EnrichSecurityResult(h.Elastic(), ipEntity, h.scanChan, h.logger)
		}()
		wgEnrich.Wait()

		// Concurrent map writes
		muUnique.Lock()
		defer muUnique.Unlock()
		uniqueIPMap[ip] = ipEntity
	})
	if err != nil {
		h.logger.Errorf("failed to initialize passive dns unique pool: %v", err)
		return
	}
	defer pUnique.Release()
	for _, ipAddress := range uniqueIP {
		wgUnique.Add(1)
		if err = pUnique.Invoke(ipAddress); err != nil {
			h.logger.Errorf("failed to invoke: %v", err)
		}
	}
	wgUnique.Wait()

	// Populate passive dns response info
	var wgResponse sync.WaitGroup
	pResponse, err := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgResponse.Done()
		data := i.(*udm.PassiveDNSDomain)
		ipEntity, ok := uniqueIPMap[data.IPAddress]
		if !ok {
			return
		}

		var wgEnrich sync.WaitGroup
		wgEnrich.Add(2)
		go func() {
			defer wgEnrich.Done()
			if ipEntity.Enrichment.Artifact != nil && len(ipEntity.Enrichment.Artifact.Data) > 0 {
				artifact := ipEntity.Enrichment.Artifact.Data[0]
				data.ASN = int(artifact.ASN)
				data.ASL = artifact.ASOwner
			}
		}()
		go func() {
			defer wgEnrich.Done()
			if ipEntity.Evaluate.SecurityResult != nil {
				riskScore := ipEntity.Evaluate.SecurityResult.RiskScore
				if riskScore != nil {
					data.RiskScore = riskScore
				}
			}
			if data.RiskScore == nil {
				data.RiskScore = new(int)
				*data.RiskScore = defs.RiskScoreUnknown
			}
		}()
		wgEnrich.Wait()
	})
	if err != nil {
		h.logger.Errorf("failed to initialize passive dns response pool: %v", err)
		return
	}
	defer pResponse.Release()
	for _, data := range responsePassiveDNS.Detail.Data {
		wgResponse.Add(1)
		if err = pResponse.Invoke(data); err != nil {
			h.logger.Errorf("failed to invoke: %v", err)
		}
	}
	wgResponse.Wait()
	// Success
	entity.Enrichment.PassiveDNSDomain = responsePassiveDNS.Detail
}

func (h *URLHandler) enrichSubdomains(entity *udm.Entity, limit int, offset int) {
	extracted := h.extractor.Extract(entity.GetValue())
	domain := extracted.FullDomain()
	if domain == "" {
		h.logger.Errorf("invalid domain for url (%s)", domain)
		return
	}
	var responseSubdomain model.ResponseEnrichmentSubdomain
	res, err := h.client.GetSubdomains(h.config.API.APIEnrichment, domain, limit, offset, &responseSubdomain)
	if err != nil {
		h.logger.Errorf("failed to get subdomains for %s: %v", domain, err)
		return
	}
	if res.StatusCode() >= rest.StatusBadRequest {
		h.logger.Errorf("failed to get subdomains for %s: status code %d", domain, res.StatusCode())
		return
	}
	// Get unique subdomains
	uniqueSubdomains := make([]string, 0)
	uniqueSubdomainsMap := make(map[string]*udm.Entity)
	for _, data := range responseSubdomain.Detail.Data {
		subdomain := data.FullDomain
		if _, ok := uniqueSubdomainsMap[subdomain]; !ok {
			uniqueSubdomains = append(uniqueSubdomains, subdomain)
			uniqueSubdomainsMap[subdomain] = &udm.Entity{}
		}
	}
	// Populate security result for each unique subdomain entity
	var wgUnique sync.WaitGroup
	var muUnique sync.Mutex
	pUnique, err := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgUnique.Done()
		subdomain := i.(string)
		subdomainEntity, err := utils.InitializeEntity(h.Elastic(), subdomain, udm.EntityTypeDomain, h.extractor, h.scanChan)
		if err != nil {
			h.logger.Errorf("failed to get subdomain entity %s: %v", subdomain, err)
			return
		}
		subdomainEntity.Evaluate = &udm.Evaluate{}
		utils.EnrichSecurityResult(h.Elastic(), subdomainEntity, h.scanChan, h.logger)
		// Concurrent map writes
		muUnique.Lock()
		defer muUnique.Unlock()
		uniqueSubdomainsMap[subdomain] = subdomainEntity
	})
	if err != nil {
		h.logger.Errorf("failed to initialize subdomain unique pool: %v", err)
		return
	}
	defer pUnique.Release()
	for _, subdomain := range uniqueSubdomains {
		wgUnique.Add(1)
		if err = pUnique.Invoke(subdomain); err != nil {
			h.logger.Errorf("failed to invoke: %v", err)
		}
	}
	wgUnique.Wait()
	// Populate subdomain response info
	var wgResponse sync.WaitGroup
	pResponse, err := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgResponse.Done()
		data := i.(*udm.Subdomain)
		subdomainEntity := uniqueSubdomainsMap[data.FullDomain]
		if subdomainEntity.Evaluate.SecurityResult != nil {
			riskScore := subdomainEntity.Evaluate.SecurityResult.RiskScore
			if riskScore != nil {
				data.RiskScore = riskScore
			}
		}
		if data.RiskScore == nil {
			data.RiskScore = new(int)
			*data.RiskScore = defs.RiskScoreUnknown
		}
	})
	if err != nil {
		h.logger.Errorf("failed to initialize subdomain response pool: %v", err)
		return
	}
	defer pResponse.Release()
	for _, subdomain := range responseSubdomain.Detail.Data {
		wgResponse.Add(1)
		if err = pResponse.Invoke(subdomain); err != nil {
			h.logger.Errorf("failed to invoke: %v", err)
		}
	}
	wgResponse.Wait()
	// Success
	entity.Enrichment.Subdomain = responseSubdomain.Detail
}

func (h *URLHandler) enrichSiblings(entity *udm.Entity, limit int, offset int) {
	extracted := h.extractor.Extract(entity.GetValue())
	domain := extracted.FullDomain()
	if domain == "" {
		h.logger.Errorf("invalid domain for url (%s)", domain)
		return
	}
	var responseSibling model.ResponseEnrichmentSibling
	res, err := h.client.GetSiblingDomains(h.config.API.APIEnrichment, domain, limit, offset, &responseSibling)
	if err != nil {
		h.logger.Errorf("failed to get sibling domains for %s: %v", domain, err)
		return
	}
	if res.StatusCode() >= rest.StatusBadRequest {
		h.logger.Errorf("failed to get sibling domains for %s: status code %d", domain, res.StatusCode())
		return
	}

	// Get unique sibling domains
	uniqueSiblings := make([]string, 0)
	uniqueSiblingsMap := make(map[string]*udm.Entity)
	for _, data := range responseSibling.Detail.Data {
		sibling := data.FullDomain
		if _, ok := uniqueSiblingsMap[sibling]; !ok {
			uniqueSiblings = append(uniqueSiblings, sibling)
			uniqueSiblingsMap[sibling] = &udm.Entity{}
		}
	}

	// Populate security result for each sibling domain entity
	var wgUnique sync.WaitGroup
	var muUnique sync.Mutex
	pUnique, err := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgUnique.Done()
		sibling := i.(string)
		siblingEntity, err := utils.InitializeEntity(h.Elastic(), sibling, udm.EntityTypeDomain, h.extractor, h.scanChan)
		if err != nil {
			h.logger.Errorf("failed to get sibling domain entity %s: %v", sibling, err)
			return
		}
		siblingEntity.Evaluate = &udm.Evaluate{}
		utils.EnrichSecurityResult(h.Elastic(), siblingEntity, h.scanChan, h.logger)
		// Concurrent map writes
		muUnique.Lock()
		defer muUnique.Unlock()
		uniqueSiblingsMap[sibling] = siblingEntity
	})
	if err != nil {
		h.logger.Errorf("failed to initialize sibling domain unique pool: %v", err)
		return
	}
	defer pUnique.Release()
	for _, sibling := range uniqueSiblings {
		wgUnique.Add(1)
		if err = pUnique.Invoke(sibling); err != nil {
			h.logger.Errorf("failed to invoke: %v", err)
		}
	}
	wgUnique.Wait()

	// Populate sibling domain response info
	var wgResponse sync.WaitGroup
	pResponse, err := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgResponse.Done()
		data := i.(*udm.SiblingDomain)
		siblingEntity := uniqueSiblingsMap[data.FullDomain]
		if siblingEntity.Evaluate.SecurityResult != nil {
			riskScore := siblingEntity.Evaluate.SecurityResult.RiskScore
			if riskScore != nil {
				data.RiskScore = riskScore
			}
		}
		if data.RiskScore == nil {
			data.RiskScore = new(int)
			*data.RiskScore = defs.RiskScoreUnknown
		}
	})
	if err != nil {
		h.logger.Errorf("failed to initialize sibling domain response pool: %v", err)
		return
	}
	defer pResponse.Release()
	for _, sibling := range responseSibling.Detail.Data {
		wgResponse.Add(1)
		if err = pResponse.Invoke(sibling); err != nil {
			h.logger.Errorf("failed to invoke: %v", err)
		}
	}
	wgResponse.Wait()
	// Success
	entity.Enrichment.SiblingDomain = responseSibling.Detail
}
