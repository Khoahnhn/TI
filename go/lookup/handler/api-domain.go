package handler

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
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
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
	"gitlab.viettelcyber.com/awesome-threat/library/tld"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

type DomainHandler struct {
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

func NewDomainHandler(ctx context.Context, conf model.Config) DomainHandlerInterface {
	handler := &DomainHandler{
		name:    defs.HandlerDomain,
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

func (h *DomainHandler) Elastic() elastic.GlobalRepository {
	// Success
	return h.elastic
}

func (h *DomainHandler) Lookup(c echo.Context) error {
	// Validate request
	req, err := h.verifyLookup(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Message(err.Error()).Log(err).Go()
	}

	// Initialize variables
	entityValue := req.Value
	// Set response entity
	entity, err := utils.InitializeEntity(h.Elastic(), entityValue, udm.EntityTypeDomain, h.extractor, h.scanChan)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	entityUrl, err := utils.InitializeEntity(h.Elastic(), fmt.Sprintf("https://%s", entityValue), udm.EntityTypeURL, h.extractor, h.scanChan)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// URL
	if _, err = utils.InitializeEntity(h.Elastic(), fmt.Sprintf("http://%s", entityValue), udm.EntityTypeURL, h.extractor, h.scanChan); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if _, err = utils.InitializeEntity(h.Elastic(), fmt.Sprintf("https://%s", entityValue), udm.EntityTypeURL, h.extractor, h.scanChan); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}

	entity.Enrichment = &udm.Enrichment{
		Whois:            &udm.ResponseEnrichmentWhois{},
		PopularityRank:   &udm.ResponseEnrichmentPopularityRank{},
		PassiveDNSDomain: &udm.ResponseEnrichmentPassiveDNSDomain{},
		Subdomain:        &udm.ResponseEnrichmentSubdomain{},
		SiblingDomain:    &udm.ResponseEnrichmentSiblingDomain{},
		LastDNSRecord:    &udm.ResponseEnrichmentDNSRecord{},
		SSLCertificate:   &udm.ResponseEnrichmentSSLCertificate{},
		HTTPRequest:      &udm.ResponseEnrichmentHTTPRequest{},
	}
	entity.Evaluate = &udm.Evaluate{}

	var wgData sync.WaitGroup
	for sct, attrs := range req.Sections {
		wgData.Add(1)
		go func(section string, limit int, offset int, flat bool) {
			defer wgData.Done()
			switch section {
			case defs.SectionPopularityRank:
				utils.EnrichRank(h.Elastic(), entity, h.scanChan, limit, offset, h.logger)
			case defs.SectionWhois:
				utils.EnrichWhois(h.Elastic(), entity, h.scanChan, limit, offset, flat, h.logger)
			case defs.SectionPassiveDNS:
				h.enrichPassiveDNS(entity, limit, offset)
			case defs.SectionDNSRecord:
				utils.EnrichDNSRecord(h.Elastic(), entity, h.scanChan, limit, offset, h.logger)
			case defs.SectionHash:
				// TODO: implement
			case defs.SectionSubdomains:
				h.enrichSubdomains(entity, limit, offset)
			case defs.SectionSiblings:
				h.enrichSiblings(entity, limit, offset)
			case defs.SectionSSLCertificate:
				utils.EnrichSSLCertificate(h.Elastic(), entity, h.scanChan, limit, offset, flat, h.logger)
			case defs.SectionRelations:
				// TODO: implement
			case defs.SectionSecurityResult:
				utils.EnrichSecurityResult(h.Elastic(), entity, h.scanChan, h.logger)
			case defs.SectionHTTPRequest:
				utils.EnrichHTTPRequest(h.Elastic(), entityUrl, h.scanChan, limit, offset, flat, h.logger)
				entity.Enrichment.HTTPRequest = entityUrl.Enrichment.HTTPRequest
			}
		}(sct, attrs.Limit, attrs.Offset, attrs.Flat)
	}
	wgData.Wait()

	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(entity).Go()
}

func (h *DomainHandler) LookupMultiple(c echo.Context) error {
	// Validate request
	req, err := h.verifyLookupMultiple(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Message(err.Error()).Log(err).Go()
	}

	data := make([]*model.LookupMultipleItem, len(req.Values))
	failed := make([]*model.LookupMultipleItem, 0)
	for _, domain := range req.Invalid {
		failed = append(failed, &model.LookupMultipleItem{
			Value: domain,
			Error: defs.ErrInvalidValueDomain,
		})
	}

	var wgLookup sync.WaitGroup
	pLookup, _ := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgLookup.Done()
		domain := i.(*model.JobLookup)
		domainEntity, err := utils.InitializeEntity(h.Elastic(), domain.Value, udm.EntityTypeDomain, h.extractor, h.scanChan)
		if err != nil {
			h.logger.Errorf("failed to initialize domain entity %s: %v", domain.Value, err)
			data[domain.Index] = nil
			return
		}
		domainEntity.Enrichment = &udm.Enrichment{}
		domainEntity.Evaluate = &udm.Evaluate{}
		domainItem := &model.LookupMultipleItem{
			Value:     domain.Value,
			FirstSeen: domainEntity.Metadata.CreationTimestamp,
			LastSeen:  domainEntity.Metadata.ModificationTimestamp,
			StatusIOC: defs.StatusIOCUnknown,
		}
		var wgEnrich sync.WaitGroup
		wgEnrich.Add(2)
		go func() {
			defer wgEnrich.Done()
			utils.EnrichWhois(h.Elastic(), domainEntity, h.scanChan, 1, 0, false, h.logger)
			if len(domainEntity.Enrichment.Whois.Data) > 0 {
				whois := domainEntity.Enrichment.Whois.Data[0]
				domainItem.CreationTime = whois.CreationTime
				domainItem.ExpirationTime = whois.ExpirationTime
				flat := whois.Flatten()
				registrar, ok := flat["Registrar Name"]
				if ok {
					domainItem.Registrar, _ = registrar.(string)
				}
				registrant, ok := flat["Registrant Name"]
				if ok {
					domainItem.Registrant, _ = registrant.(string)
				}
			}
		}()
		go func() {
			defer wgEnrich.Done()
			utils.EnrichSecurityResult(h.Elastic(), domainEntity, h.scanChan, h.logger)
			securityResult := domainEntity.Evaluate.SecurityResult
			if securityResult != nil {
				riskScore := securityResult.RiskScore
				if riskScore != nil {
					domainItem.RiskScore = riskScore
				}
				domainItem.PrivateVTI = securityResult.PrivateVTI
				domainItem.Categories = securityResult.Categories
				if securityResult.PrivateVTI {
					domainItem.StatusIOC = defs.StatusIOCExclusive
				}
			}
			if domainItem.RiskScore == nil {
				domainItem.RiskScore = new(int)
				*domainItem.RiskScore = defs.RiskScoreUnknown
			}
			if domainItem.Categories == nil {
				domainItem.Categories = make([]string, 0)
			}
		}()
		wgEnrich.Wait()
		data[domain.Index] = domainItem
	})
	defer pLookup.Release()
	for idx, domain := range req.Values {
		wgLookup.Add(1)
		if err = pLookup.Invoke(&model.JobLookup{Value: domain, Index: idx}); err != nil {
			h.logger.Errorf("failed to invoke: %v", err)
		}
	}
	wgLookup.Wait()
	results := make([]*model.LookupMultipleItem, 0)
	for _, doc := range data {
		if doc != nil {
			results = append(results, doc)
		}
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(model.ResponseLookupMultiple{
		Data:   results,
		Failed: failed,
	}).Go()
}

func (h *DomainHandler) verifyLookup(c echo.Context) (req model.RequestLookupSingle, err error) {
	// Bind
	if err = Validate(c, &req); err != nil {
		return req, err
	}
	// Validate
	req.Value = strings.ToLower(strings.TrimSuffix(req.Value, "/"))
	if !utils.IsDomain(req.Value) {
		return req, errors.New(defs.ErrInvalidValueDomain)
	}
	// Validate Sections
	if len(req.Sections) > 0 {
		for section, attrs := range req.Sections {
			if _, ok := defs.EnumSectionDomain[section]; !ok {
				return req, fmt.Errorf(defs.ErrInvalidSection, section)
			}
			attrs.Limit = min(attrs.Limit, defs.DefaultMaxLimit)
		}
	} else {
		sections := make(map[string]*model.RequestSection)
		for section := range defs.EnumSectionDomain {
			sections[section] = &model.RequestSection{}
		}
		req.Sections = sections
	}
	// Success
	return req, nil
}

func (h *DomainHandler) verifyLookupMultiple(c echo.Context) (req model.RequestLookupMultiple, err error) {
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
		req.Values[i] = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(req.Values[i], "/")))
	}
	req.Values = slice.String(req.Values).Unique().Extract()
	sort.Strings(req.Values)
	// Filter domains
	validDomains := make([]string, 0)
	req.Invalid = make([]string, 0)
	for i := range req.Values {
		domain := req.Values[i]
		if !utils.IsDomain(domain) {
			req.Invalid = append(req.Invalid, domain)
		} else {
			validDomains = append(validDomains, domain)
		}
	}
	req.Values = validDomains
	// Success
	return req, nil
}

func (h *DomainHandler) enrichPassiveDNS(entity *udm.Entity, limit int, offset int) {
	var responsePassiveDNS model.ResponseEnrichmentPassiveDNSDomain
	res, err := h.client.GetDomainPassiveDNS(h.config.API.APIEnrichment, entity.GetValue(), limit, offset, &responsePassiveDNS)
	if err != nil {
		h.logger.Errorf("failed to get passive dns for %s: %v", entity.GetValue(), err)
		return
	}
	if res.StatusCode() >= rest.StatusBadRequest {
		h.logger.Errorf("failed to get passive dns for %s: status code %d", entity.GetValue(), res.StatusCode())
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
		if ipEntity == nil {
			h.logger.Debugf("ip entity is nil for %s (possibly due to 429 or not found)", ip)
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
		if !ok || ipEntity == nil {
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
				riskScore := defs.RiskScoreUnknown
				data.RiskScore = &riskScore
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

func (h *DomainHandler) enrichSubdomains(entity *udm.Entity, limit int, offset int) {
	var responseSubdomain model.ResponseEnrichmentSubdomain
	res, err := h.client.GetSubdomains(h.config.API.APIEnrichment, entity.GetValue(), limit, offset, &responseSubdomain)
	if err != nil {
		h.logger.Errorf("failed to get subdomains for %s: %v", entity.GetValue(), err)
		return
	}
	if res.StatusCode() >= rest.StatusBadRequest {
		h.logger.Errorf("failed to get subdomains for %s: status code %d", entity.GetValue(), res.StatusCode())
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

func (h *DomainHandler) enrichSiblings(entity *udm.Entity, limit int, offset int) {
	var responseSibling model.ResponseEnrichmentSibling
	res, err := h.client.GetSiblingDomains(h.config.API.APIEnrichment, entity.GetValue(), limit, offset, &responseSibling)
	if err != nil {
		h.logger.Errorf("failed to get sibling domains for %s: %v", entity.GetValue(), err)
		return
	}
	if res.StatusCode() >= rest.StatusBadRequest {
		h.logger.Errorf("failed to get sibling domains for %s: status code %d", entity.GetValue(), res.StatusCode())
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

	// Populate siblig domain response info
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
