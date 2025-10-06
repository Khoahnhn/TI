package utils

import (
	"ws-lookup/adapter/elastic"

	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

func EnrichRank(udmRepo elastic.GlobalRepository, entity *udm.Entity, scanChan chan *udm.EntityJob, limit int, offset int, logger pencil.Logger) {
	// Initialize
	popularityRankResponse := udm.ResponseEnrichmentPopularityRank{}
	// Get popularity rank count
	countRank, err := GetRelationshipsCount(udmRepo, entity, udm.RelationshipTypePopularityRank)
	if err != nil {
		logger.Errorf("failed to get popularity rank count for %s: %v", entity.GetValue(), err)
	}
	popularityRankResponse.Total = countRank
	if limit == 0 {
		return
	}
	// Get popularity rank data
	popularityRanks := make([]*udm.PopularityRank, 0)
	rankEntities, err := GetEntitiesFromRelationships(udmRepo, entity, udm.RelationshipTypePopularityRank, udm.EntityTypePopularityRank, true, []string{"-metadata.modification_timestamp"}, limit, offset, logger)
	if err != nil {
		logger.Errorf("failed to get popularity rank entities from relationships for domain %s: %v", entity.GetValue(), err)
	}
	for _, rankEntity := range rankEntities {
		if rankEntity.Noun.PopularityRank != nil {
			popularityRanks = append(popularityRanks, rankEntity.Noun.PopularityRank)
		}
	}
	popularityRankResponse.Data = popularityRanks
	entity.Enrichment.PopularityRank = &popularityRankResponse
	// Rescan Domain Popularity Ranks
	scanChan <- &udm.EntityJob{
		Entity:              *entity,
		CollectedEntityType: udm.EntityTypePopularityRank,
	}
}

func EnrichWhois(udmRepo elastic.GlobalRepository, entity *udm.Entity, scanChan chan *udm.EntityJob, limit int, offset int, flat bool, logger pencil.Logger) {
	// Initialize
	whoisResponse := udm.ResponseEnrichmentWhois{}
	countWhois, err := GetRelationshipsCount(udmRepo, entity, udm.RelationshipTypeWhois)
	if err != nil {
		logger.Errorf("failed to get whois count for %s: %v", entity.GetValue(), err)
	}
	whoisResponse.Total = countWhois
	if limit == 0 {
		entity.Enrichment.Whois = &whoisResponse
		return
	}
	// Get whois data
	whois := make([]*udm.Whois, 0)
	whoisEntities, err := GetEntitiesFromRelationships(udmRepo, entity, udm.RelationshipTypeWhois, udm.EntityTypeWhois, true, []string{"-metadata.modification_timestamp"}, limit, offset, logger)
	if err != nil {
		logger.Errorf("failed to get whois entities from relationships for domain %s: %v", entity.GetValue(), err)
	}
	for _, whoisEntity := range whoisEntities {
		if flat {
			whois = append(whois, &udm.Whois{Flat: whoisEntity.Noun.Whois.Flatten()})
		} else {
			whois = append(whois, whoisEntity.Noun.Whois)
		}
	}
	whoisResponse.Data = whois
	entity.Enrichment.Whois = &whoisResponse
	// Rescan Domain Whois
	scanChan <- &udm.EntityJob{
		Entity:              *entity,
		CollectedEntityType: udm.EntityTypeWhois,
	}
}

func EnrichDNSRecord(udmRepo elastic.GlobalRepository, entity *udm.Entity, scanChan chan *udm.EntityJob, limit int, offset int, logger pencil.Logger) {
	// Initialize
	dnsResponse := udm.ResponseEnrichmentDNSRecord{}
	// Get DNS record count
	if limit == 0 {
		countDNSRecord, err := GetRelationshipsCount(udmRepo, entity, udm.RelationshipTypeDNSRecord)
		if err != nil {
			logger.Errorf("failed to get dns record count for %s: %v", entity.GetValue(), err)
		}
		dnsResponse.Total = countDNSRecord
		entity.Enrichment.LastDNSRecord = &dnsResponse
		return
	}
	// Get DNS record data
	dnsRecord := make([]*udm.DNSRecord, 0)
	dnsRecordEntities, err := GetEntitiesFromRelationships(udmRepo, entity, udm.RelationshipTypeDNSRecord, udm.EntityTypeDNSRecord, true, []string{"-metadata.modification_timestamp"}, limit, offset, logger)
	if err != nil {
		logger.Errorf("failed to get dns record entities from relationships for domain %s: %v", entity.GetValue(), err)
	}
	for _, dnsRecordEntity := range dnsRecordEntities {
		if dnsRecordEntity.Noun.DNSRecord != nil {
			dnsRecord = append(dnsRecord, dnsRecordEntity.Noun.DNSRecord)
		}
	}
	dnsResponse.Data = dnsRecord
	dnsResponse.Total = int64(len(dnsRecord))
	entity.Enrichment.LastDNSRecord = &dnsResponse
	// Rescan Domain Whois
	scanChan <- &udm.EntityJob{
		Entity:              *entity,
		CollectedEntityType: udm.EntityTypeDNSRecord,
	}
}

func EnrichArtifact(udmRepo elastic.GlobalRepository, entity *udm.Entity, scanChan chan *udm.EntityJob, limit int, offset int, flat bool, logger pencil.Logger) {
	// Initialize
	artifactResponse := udm.ResponseEnrichmentArtifact{}
	// Get artifact count
	countArtifact, err := GetRelationshipsCount(udmRepo, entity, udm.RelationshipTypeArtifact)
	if err != nil {
		logger.Errorf("failed to get artifact count for %s: %v", entity.GetValue(), err)
	}
	artifactResponse.Total = countArtifact
	if limit == 0 {
		entity.Enrichment.Artifact = &artifactResponse
		return
	}
	// Get artifact data
	artifacts := make([]*udm.Artifact, 0)
	artifactEntities, err := GetEntitiesFromRelationships(udmRepo, entity, udm.RelationshipTypeArtifact, udm.EntityTypeArtifact, true, []string{"-metadata.modification_timestamp"}, limit, offset, logger)
	if err != nil {
		logger.Errorf("failed to get artifact entities from relationships for IP %s: %v", entity.GetValue(), err)
	}
	for _, artifactEntity := range artifactEntities {
		if flat {
			artifacts = append(artifacts, &udm.Artifact{Flat: artifactEntity.Noun.Artifact.Flatten()})
		} else {
			artifacts = append(artifacts, artifactEntity.Noun.Artifact)
		}
	}
	artifactResponse.Data = artifacts
	entity.Enrichment.Artifact = &artifactResponse
	// Rescan IP Artifact
	scanChan <- &udm.EntityJob{
		Entity:              *entity,
		CollectedEntityType: udm.EntityTypeArtifact,
	}
}

func EnrichSSLCertificate(udmRepo elastic.GlobalRepository, entity *udm.Entity, scanChan chan *udm.EntityJob, limit int, offset int, flat bool, logger pencil.Logger) {
	// Initialize
	sslCertificateResponse := udm.ResponseEnrichmentSSLCertificate{}
	// Get artifact count
	countSSLCertificate, err := GetRelationshipsCount(udmRepo, entity, udm.RelationshipTypeSSLCertificate)
	if err != nil {
		logger.Errorf("failed to get ssl certificate count for %s: %v", entity.GetValue(), err)
	}
	sslCertificateResponse.Total = countSSLCertificate
	if limit == 0 {
		entity.Enrichment.SSLCertificate = &sslCertificateResponse
		return
	}
	// Get certificate data
	sslCertificates := make([]*udm.SSLCertificate, 0)
	sslCertificateEntities, err := GetEntitiesFromRelationships(udmRepo, entity, udm.RelationshipTypeSSLCertificate, udm.EntityTypeSSLCertificate, true, []string{"-metadata.valid_to_timestamp"}, limit, offset, logger)
	if err != nil {
		logger.Errorf("failed to get ssl certificate entities from relationships for IP %s: %v", entity.GetValue(), err)
	}
	for _, sslCertificateEntity := range sslCertificateEntities {
		if flat {
			sslCertificates = append(sslCertificates, &udm.SSLCertificate{Flat: sslCertificateEntity.Noun.SSLCertificate.Flatten()})
		} else {
			sslCertificates = append(sslCertificates, sslCertificateEntity.Noun.SSLCertificate)
		}
	}
	sslCertificateResponse.Data = sslCertificates
	entity.Enrichment.SSLCertificate = &sslCertificateResponse
	// Rescan SSL Certificate
	scanChan <- &udm.EntityJob{
		Entity:              *entity,
		CollectedEntityType: udm.EntityTypeSSLCertificate,
	}
}

func EnrichHTTPRequest(udmRepo elastic.GlobalRepository, entity *udm.Entity, scanChan chan *udm.EntityJob, limit int, offset int, flat bool, logger pencil.Logger) {
	// Initialize
	httpRequestResponse := udm.ResponseEnrichmentHTTPRequest{}
	// Get artifact count
	countHTTPRequest, err := GetRelationshipsCount(udmRepo, entity, udm.RelationshipTypeHTTPRequest)
	if err != nil {
		logger.Errorf("failed to get http request count for %s: %v", entity.GetValue(), err)
	}
	httpRequestResponse.Total = countHTTPRequest
	if limit == 0 {
		entity.Enrichment.HTTPRequest = &httpRequestResponse
		return
	}
	// Get certificate data
	httpRequests := make([]*udm.HTTPRequest, 0)
	httpRequestEntities, err := GetEntitiesFromRelationships(udmRepo, entity, udm.RelationshipTypeHTTPRequest, udm.EntityTypeHTTPRequest, true, []string{"-metadata.modification_timestamp"}, limit, offset, logger)
	if err != nil {
		logger.Errorf("failed to get http request entities from relationships for url %s: %v", entity.GetValue(), err)
	}
	for _, httpRequestEntity := range httpRequestEntities {
		if httpRequestEntity.Noun.HTTPRequest != nil {
			if flat {
				httpRequests = append(httpRequests, &udm.HTTPRequest{Flat: httpRequestEntity.Noun.HTTPRequest.Flatten()})
			} else {
				httpRequests = append(httpRequests, httpRequestEntity.Noun.HTTPRequest)
			}
		}
	}
	httpRequestResponse.Data = httpRequests
	httpRequestResponse.Total = int64(len(httpRequests))
	entity.Enrichment.HTTPRequest = &httpRequestResponse
	// Rescan Domain Whois
	scanChan <- &udm.EntityJob{
		Entity:              *entity,
		CollectedEntityType: udm.EntityTypeHTTPRequest,
	}
}

func EnrichSecurityResult(udmRepo elastic.GlobalRepository, entity *udm.Entity, scanChan chan *udm.EntityJob, logger pencil.Logger) {
	var securityResult *udm.SecurityResult
	var expired bool

	securityResultEntities, err := GetEntitiesFromRelationships(udmRepo, entity, udm.RelationshipTypeSecurityResult, udm.EntityTypeSecurityResult, true, []string{"-metadata.modification_timestamp"}, 1, 0, logger)
	if err != nil {
		logger.Errorf("failed to get security result entities from relationships for %s: %v", entity.GetValue(), err)
	}
	if len(securityResultEntities) > 0 {
		securityResult = securityResultEntities[0].Noun.SecurityResult
		securityResult.Tags = make([]string, 0)
		expired = securityResultEntities[0].IsExpired()
	}

	if securityResult == nil || expired {
		// Rescan Security Result
		scanChan <- &udm.EntityJob{
			Entity:              *entity,
			CollectedEntityType: udm.EntityTypeSecurityResult,
		}
	}
	// Success
	entity.Evaluate.SecurityResult = securityResult
}
