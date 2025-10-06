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

type IPAddressHandler struct {
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

func NewIPAddressHandler(ctx context.Context, conf model.Config) IPAddressHandlerInterface {
	handler := &IPAddressHandler{
		name:    defs.HandlerIPAddress,
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

func (h *IPAddressHandler) Elastic() elastic.GlobalRepository {
	// Success
	return h.elastic
}

func (h *IPAddressHandler) Lookup(c echo.Context) error {
	// Validate request
	req, err := h.verifyLookup(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Message(err.Error()).Log(err).Go()
	}

	// Initialize variables
	entityValue := req.Value
	// Check if IP is private
	if utils.IsPrivateIP(entityValue) {
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"private": true}).Message(defs.ErrPrivateIP).Go()
	}
	// Set response entity
	entity, err := utils.InitializeEntity(h.Elastic(), entityValue, udm.EntityTypeIPAddress, h.extractor, h.scanChan)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}

	entity.Enrichment = &udm.Enrichment{
		PassiveDNSIPAddress: &udm.ResponseEnrichmentPassiveDNSIPAddress{},
		Subnet:              &udm.ResponseEnrichmentSubnet{},
		SSLCertificate:      &udm.ResponseEnrichmentSSLCertificate{},
	}
	entity.Evaluate = &udm.Evaluate{}

	var wgData sync.WaitGroup
	for sct, attrs := range req.Sections {
		wgData.Add(1)
		go func(section string, limit int, offset int, flat bool) {
			defer wgData.Done()
			switch section {
			case defs.SectionArtifact:
				utils.EnrichArtifact(h.Elastic(), entity, h.scanChan, limit, offset, flat, h.logger)
			case defs.SectionPassiveDNS:
				h.enrichPassiveDNS(entity, limit, offset)
			case defs.SectionHash:
				// TODO: implement
			case defs.SectionSubnet:
				h.enrichSubnet(entity, limit, offset)
			case defs.SectionSSLCertificate:
				utils.EnrichSSLCertificate(h.Elastic(), entity, h.scanChan, limit, offset, flat, h.logger)
			case defs.SectionRelations:
				// TODO: implement
			case defs.SectionSecurityResult:
				utils.EnrichSecurityResult(h.Elastic(), entity, h.scanChan, h.logger)
			}
		}(sct, attrs.Limit, attrs.Offset, attrs.Flat)
	}
	wgData.Wait()

	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(entity).Go()
}

func (h *IPAddressHandler) LookupMultiple(c echo.Context) error {
	// Validate request
	req, err := h.verifyLookupMultiple(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Message(err.Error()).Go()
	}

	data := make([]*model.LookupMultipleItem, len(req.Values))
	failed := make([]*model.LookupMultipleItem, 0)
	for _, ip := range req.Values {
		if utils.IsPrivateIP(ip) {
			failed = append(failed, &model.LookupMultipleItem{
				Value: ip,
				Error: defs.ErrPrivateIP,
			})
		}
	}
	for _, ip := range req.Invalid {
		failed = append(failed, &model.LookupMultipleItem{
			Value: ip,
			Error: defs.ErrInvalidValueIP,
		})
	}

	var wgLookup sync.WaitGroup
	pLookup, _ := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgLookup.Done()
		ip := i.(*model.JobLookup)
		if utils.IsPrivateIP(ip.Value) {
			data[ip.Index] = nil
			return
		}
		ipEntity, err := utils.InitializeEntity(h.Elastic(), ip.Value, udm.EntityTypeIPAddress, h.extractor, h.scanChan)
		if err != nil {
			h.logger.Errorf("failed to initialize ip entity %s: %v", ip.Value, err)
			data[ip.Index] = nil
			return
		}
		ipEntity.Enrichment = &udm.Enrichment{}
		ipEntity.Evaluate = &udm.Evaluate{}
		ipItem := &model.LookupMultipleItem{
			Value:     ip.Value,
			FirstSeen: ipEntity.Metadata.CreationTimestamp,
			LastSeen:  ipEntity.Metadata.ModificationTimestamp,
			StatusIOC: defs.StatusIOCUnknown,
		}
		var wgEnrich sync.WaitGroup
		wgEnrich.Add(2)
		go func() {
			defer wgEnrich.Done()
			utils.EnrichArtifact(h.Elastic(), ipEntity, h.scanChan, 1, 0, false, h.logger)
			if len(ipEntity.Enrichment.Artifact.Data) > 0 {
				artifact := ipEntity.Enrichment.Artifact.Data[0]
				flat := artifact.Flatten()
				if value, ok := flat["Location"]; ok {
					ipItem.Location, _ = value.(string)
				}
				ipItem.ASN = int(artifact.ASN)
				ipItem.ASL = artifact.ASOwner
				ipItem.Subnet = artifact.Subnet
			}
		}()
		go func() {
			defer wgEnrich.Done()
			utils.EnrichSecurityResult(h.Elastic(), ipEntity, h.scanChan, h.logger)
			securityResult := ipEntity.Evaluate.SecurityResult
			if securityResult != nil {
				riskScore := securityResult.RiskScore
				if riskScore != nil {
					ipItem.RiskScore = riskScore
				}
				ipItem.PrivateVTI = securityResult.PrivateVTI
				ipItem.Categories = securityResult.Categories
				if securityResult.PrivateVTI {
					ipItem.StatusIOC = defs.StatusIOCExclusive
				}
			}
			if ipItem.RiskScore == nil {
				ipItem.RiskScore = new(int)
				*ipItem.RiskScore = defs.RiskScoreUnknown
			}
			if ipItem.Categories == nil {
				ipItem.Categories = make([]string, 0)
			}
		}()
		wgEnrich.Wait()
		data[ip.Index] = ipItem
	})
	defer pLookup.Release()

	for idx, ip := range req.Values {
		wgLookup.Add(1)
		if err = pLookup.Invoke(&model.JobLookup{Value: ip, Index: idx}); err != nil {
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

func (h *IPAddressHandler) verifyLookup(c echo.Context) (req model.RequestLookupSingle, err error) {
	// Bind
	if err = Validate(c, &req); err != nil {
		return req, err
	}
	req.Value = strings.ToLower(strings.TrimSpace(req.Value))
	// Validate
	if !utils.IsIP(req.Value) {
		return req, errors.New(defs.ErrInvalidValueIP)
	}
	// Validate Sections
	if len(req.Sections) > 0 {
		for section, attrs := range req.Sections {
			if _, ok := defs.EnumSectionIPAddress[section]; !ok {
				return req, fmt.Errorf(defs.ErrInvalidSection, section)
			}
			attrs.Limit = min(attrs.Limit, defs.DefaultMaxLimit)
		}
	} else {
		sections := make(map[string]*model.RequestSection)
		for section := range defs.EnumSectionIPAddress {
			sections[section] = &model.RequestSection{}
		}
		req.Sections = sections
	}
	// Success
	return req, nil
}

func (h *IPAddressHandler) verifyLookupMultiple(c echo.Context) (req model.RequestLookupMultiple, err error) {
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
		req.Values[i] = strings.TrimSpace(strings.ToLower(req.Values[i]))
	}
	req.Values = slice.String(req.Values).Unique().Extract()
	sort.Strings(req.Values)
	// Filter IPs
	validIPs := make([]string, 0)
	req.Invalid = make([]string, 0)
	for i := range req.Values {
		ip := req.Values[i]
		if !utils.IsIP(ip) {
			req.Invalid = append(req.Invalid, ip)
		} else {
			validIPs = append(validIPs, ip)
		}
	}
	req.Values = validIPs
	// Success
	return req, nil
}

func (h *IPAddressHandler) enrichPassiveDNS(entity *udm.Entity, limit int, offset int) {
	var responsePassiveDNS model.ResponseEnrichmentPassiveDNSIPAddress
	res, err := h.client.GetIPAddressPassiveDNS(h.config.API.APIEnrichment, entity.GetValue(), limit, offset, &responsePassiveDNS)
	if err != nil {
		h.logger.Errorf("failed to get passive dns for %s: %v", entity.GetValue(), err)
		return
	}
	if res.StatusCode() >= rest.StatusBadRequest {
		h.logger.Errorf("failed to get passive dns for %s: status code %d", entity.GetValue(), res.StatusCode())
		return
	}

	// Get unique domains from passive DNS records
	uniqueDomains := make([]string, 0) // Required since concurrent map read/write not allowed
	uniqueDomainsMap := make(map[string]*udm.Entity)
	for _, data := range responsePassiveDNS.Detail.Data {
		domain := data.Domain
		if _, ok := uniqueDomainsMap[domain]; !ok {
			uniqueDomains = append(uniqueDomains, domain)
			uniqueDomainsMap[domain] = &udm.Entity{}
		}
	}

	// Populate whois and security result for each unique domain entity
	var wgUnique sync.WaitGroup
	var muUnique sync.Mutex
	pUnique, err := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgUnique.Done()
		domain := i.(string)
		domainEntity, err := utils.InitializeEntity(h.Elastic(), domain, udm.EntityTypeDomain, h.extractor, h.scanChan)
		if err != nil {
			h.logger.Errorf("failed to get domain entity %s: %v", domain, err)
			return
		}

		if domainEntity == nil {
			h.logger.Debugf("domain entity is nil for %s (possibly due to error or 429)", domain)
			return
		}

		domainEntity.Enrichment = &udm.Enrichment{}
		domainEntity.Evaluate = &udm.Evaluate{}

		var wgEnrich sync.WaitGroup
		wgEnrich.Add(2)
		go func() {
			defer wgEnrich.Done()
			utils.EnrichWhois(h.Elastic(), domainEntity, h.scanChan, 1, 0, false, h.logger)
		}()
		go func() {
			defer wgEnrich.Done()
			utils.EnrichSecurityResult(h.Elastic(), domainEntity, h.scanChan, h.logger)

		}()
		wgEnrich.Wait()

		// Concurrent map writes
		muUnique.Lock()
		defer muUnique.Unlock()
		uniqueDomainsMap[domain] = domainEntity
	})
	if err != nil {
		h.logger.Errorf("failed to initialize passive dns unique pool: %v", err)
		return
	}
	defer pUnique.Release()
	for _, domain := range uniqueDomains {
		wgUnique.Add(1)
		if err = pUnique.Invoke(domain); err != nil {
			h.logger.Errorf("failed to invoke: %v", err)
		}
	}
	wgUnique.Wait()

	// Populate passive dns response info
	var wgResponse sync.WaitGroup
	pResponse, err := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgResponse.Done()
		data := i.(*udm.PassiveDNSIPAddress)
		domainEntity, ok := uniqueDomainsMap[data.Domain]
		if !ok || domainEntity == nil {
			return
		}

		var wgEnrich sync.WaitGroup
		wgEnrich.Add(2)
		go func() {
			defer wgEnrich.Done()
			if domainEntity.Enrichment.Whois != nil && len(domainEntity.Enrichment.Whois.Data) > 0 {
				whois := domainEntity.Enrichment.Whois.Data[0]
				registrar := whois.Registrar
				if registrar != nil {
					data.Registrar = registrar.CompanyName
				}
			}
		}()
		go func() {
			defer wgEnrich.Done()
			if domainEntity.Evaluate.SecurityResult != nil {
				riskScore := domainEntity.Evaluate.SecurityResult.RiskScore
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
	for _, passiveDNS := range responsePassiveDNS.Detail.Data {
		wgResponse.Add(1)
		if err = pResponse.Invoke(passiveDNS); err != nil {
			h.logger.Errorf("failed to invoke: %v", err)
		}
	}
	wgResponse.Wait()
	// Success
	entity.Enrichment.PassiveDNSIPAddress = responsePassiveDNS.Detail
}

func (h *IPAddressHandler) enrichSubnet(entity *udm.Entity, limit int, offset int) {
	var responseSubnet model.ResponseEnrichmentSubnet
	res, err := h.client.GetSubnet(h.config.API.APIEnrichment, entity.GetValue(), limit, offset, &responseSubnet)
	if err != nil {
		h.logger.Errorf("failed to get subnet for %s: %v", entity.GetValue(), err)
		return
	}
	if res.StatusCode() >= rest.StatusBadRequest {
		h.logger.Errorf("failed to get subnet for %s: status code %d", entity.GetValue(), res.StatusCode())
		return
	}

	var wgSubnet sync.WaitGroup
	p, err := ants.NewPoolWithFunc(5, func(i interface{}) {
		defer wgSubnet.Done()
		data := i.(*udm.PassiveDNSIPAddress)
		ipEntity, err := utils.InitializeEntity(h.Elastic(), data.IPAddress, udm.EntityTypeIPAddress, h.extractor, h.scanChan)
		if err != nil {
			h.logger.Errorf("failed to get ip address entity %s: %v", data, err)
			return
		}
		ipEntity.Enrichment = &udm.Enrichment{}
		ipEntity.Evaluate = &udm.Evaluate{}

		var wgEnrich sync.WaitGroup
		wgEnrich.Add(2)
		go func() {
			defer wgEnrich.Done()
			h.enrichPassiveDNS(ipEntity, 1, 0)
		}()
		go func() {
			defer wgEnrich.Done()
			utils.EnrichSecurityResult(h.Elastic(), ipEntity, h.scanChan, h.logger)
		}()
		wgEnrich.Wait()

		if ipEntity.Enrichment.PassiveDNSIPAddress != nil && len(ipEntity.Enrichment.PassiveDNSIPAddress.Data) > 0 {
			data.Domain = ipEntity.Enrichment.PassiveDNSIPAddress.Data[0].Domain
			data.ResolutionTime = ipEntity.Enrichment.PassiveDNSIPAddress.Data[0].ResolutionTime
		}

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
	})
	if err != nil {
		h.logger.Errorf("failed to initialize subnet pool: %v", err)
		return
	}
	defer p.Release()
	for _, ip := range responseSubnet.Detail.Data {
		wgSubnet.Add(1)
		if err = p.Invoke(ip); err != nil {
			h.logger.Errorf("failed to invoke: %v", err)
		}
	}
	wgSubnet.Wait()
	// Success
	entity.Enrichment.Subnet = responseSubnet.Detail
}
