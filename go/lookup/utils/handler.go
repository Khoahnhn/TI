package utils

import (
	"context"
	"fmt"
	"os"
	"time"

	"ws-lookup/adapter/elastic"
	"ws-lookup/adapter/kafka"
	"ws-lookup/defs"
	"ws-lookup/model"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/tld"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

func InitializeLogger(name string) pencil.Logger {
	logger, err := pencil.New(name, pencil.DebugLevel, true, os.Stdout)
	if err != nil {
		panic(fmt.Errorf("failed to initialize %s logger: %w", name, err))
	}
	// Success
	return logger
}

func InitializeExtractor() tld.Service {
	tldCachePath := os.Getenv(defs.EnvTldCachePath)
	if tldCachePath == "" {
		tldCachePath = defs.DefaultTLDCacheFilePath
	}
	// Success
	return tld.NewService(tldCachePath)
}

func InitializeProducers(ctx context.Context, conf *model.Config) (kafka.Producer, kafka.Producer) {
	producerEnrich, err := kafka.NewProducer(ctx, conf.Adapter.Kafka.Producers.Enrichment,
		conf.Adapter.Kafka.Topics.CollectEnrichmentTopic)
	if err != nil {
		panic(fmt.Errorf("failed to initialize enrich producer: %w", err))
	}
	producerEvaluate, err := kafka.NewProducer(ctx, conf.Adapter.Kafka.Producers.Evaluate,
		conf.Adapter.Kafka.Topics.CollectEvaluateTopic)
	if err != nil {
		panic(fmt.Errorf("failed to initialize evaluate producer: %w", err))
	}
	// Success
	return producerEnrich, producerEvaluate
}

func InitializeEntity(udmRepo elastic.GlobalRepository, entityValue string, entityType udm.EntityType, extractor tld.Service, scanChan chan *udm.EntityJob) (*udm.Entity, error) {
	entityID := hash.SHA1(fmt.Sprintf("%s--%s", entityValue, entityType))
	entity, err := udmRepo.UDM().Object().Get(entityID, entityType)
	if err != nil {
		return nil, err
	}
	// Initialize UDM entity if nonexistent
	if entity == nil {
		emptyEntity := udm.NewEntity(entityValue, entityType)
		// Populate entity noun
		switch entityType {
		case udm.EntityTypeDomain:
			extracted := extractor.Extract("http://" + entityValue)
			emptyEntity.Noun.Domain = &udm.Domain{
				Name: entityValue,
				TLD:  extracted.TLD,
				Root: extracted.Root,
				Sub:  extracted.Sub,
			}
		case udm.EntityTypeIPAddress:
			ipType := udm.IPTypeIPv4
			if IsIPv6(entityValue) {
				ipType = udm.IPTypeIPv6
			}
			emptyEntity.Noun.IP = &udm.IP{
				IP:       entityValue,
				IPNumber: IPToInt(entityValue, ipType),
				Type:     ipType,
			}
		case udm.EntityTypeURL:
			extracted := extractor.Extract(entityValue)
			emptyEntity.Noun.URL = &udm.URL{
				URL:    entityValue,
				Domain: extracted.FullDomain(),
			}
		case udm.EntityTypeFile:
			emptyEntity.Noun.File = &udm.File{}
			switch {
			case IsMD5(entityValue):
				emptyEntity.Noun.File.MD5 = entityValue
			case IsSHA1(entityValue):
				emptyEntity.Noun.File.SHA1 = entityValue
			case IsSHA256(entityValue):
				emptyEntity.Noun.File.SHA256 = entityValue
			case IsSHA512(entityValue):
				emptyEntity.Noun.File.SHA512 = entityValue
			}
		}
		// Insert new entity into DB
		if err = udmRepo.UDM().Object().InsertOne(emptyEntity, emptyEntity.GetType()); err != nil {
			return nil, err
		}
		// Publish scan requests
		scanChan <- &udm.EntityJob{
			Entity:              *emptyEntity,
			CollectedEntityType: "",
		} // Enrichment
		scanChan <- &udm.EntityJob{
			Entity:              *emptyEntity,
			CollectedEntityType: udm.EntityTypeSecurityResult,
		} // Evaluate
		entity = emptyEntity
	}
	entity.Metadata.Tags = make([]string, 0)
	entity.Enrichment = &udm.Enrichment{}
	entity.Evaluate = &udm.Evaluate{}
	// Success
	return entity, nil
}

func HandleScanRequests(scanChan chan *udm.EntityJob, producerEnrich kafka.Producer, producerEvaluate kafka.Producer, topics model.KafkaTopicsConfig, logger pencil.Logger) {
	for msg := range scanChan {
		go func(job *udm.EntityJob) {
			switch job.CollectedEntityType {
			case udm.EntityTypeSecurityResult:
				if err := producerEvaluate.Produce(job, topics.CollectEvaluateTopic); err != nil {
					logger.Errorf("failed to produce security result scan request for %s: %+v", job.Entity.GetValue(), err)
				}
			case udm.EntityType("passive_dns"):
				timeNow := clock.UnixMilli(time.Now())
				if err := producerEnrich.Produce(model.DNSCrawlMessage{
					ID:        hash.SHA1(fmt.Sprintf("%s--%s", job.Entity.GetValue(), defs.SourceVTIDatamining)),
					Source:    defs.SourceVTIDatamining,
					Value:     job.Entity.GetValue(),
					Published: timeNow,
					Crawled:   timeNow,
				}, topics.DNSCollectTopic); err != nil {
					logger.Errorf("failed to produce dns scan request for %s: %+v", job.Entity.GetValue(), err)
				}
			default:
				if err := producerEnrich.Produce(job, topics.CollectEnrichmentTopic); err != nil {
					logger.Errorf("failed to produce enrichment scan request for %s: %+v", job.Entity.GetValue(), err)
				}
			}
		}(msg)
	}
}

func GetEntitiesFromRelationships(udmRepo elastic.GlobalRepository, sourceEntity *udm.Entity, relationshipType udm.RelationshipType, targetEntityType udm.EntityType, includeExpired bool, sorts []string, size int, offset int, logger pencil.Logger) ([]*udm.Entity, error) {
	entities := make([]*udm.Entity, 0)
	relationships, err := udmRepo.UDM().Object().GetTargetRelationships(sourceEntity.GetID(), sourceEntity.GetType(), relationshipType, sorts, size, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s relationships from DB: %+v", relationshipType, err)
	} else {
		for _, entity := range relationships {
			relationship := entity.Noun.Relationship
			entityDoc, err := udmRepo.UDM().Object().Get(relationship.TargetEntityID, targetEntityType)
			if err != nil {
				logger.Errorf("failed to fetch %s entity from DB: %+v", relationshipType, err)
				continue
			} else if entityDoc != nil {
				if !includeExpired && entityDoc.IsExpired() {
					continue
				}
				entities = append(entities, entityDoc)
			}
		}
	}
	return entities, nil
}

func GetRelationshipsCount(udmRepo elastic.GlobalRepository, entity *udm.Entity, relationshipType udm.RelationshipType) (int64, error) {
	relationshipCount, err := udmRepo.UDM().Object().CountTargetRelationships(entity.GetID(), entity.GetType(), relationshipType)
	if err != nil {
		return 0, err
	}
	// Success
	return relationshipCount, nil
}
