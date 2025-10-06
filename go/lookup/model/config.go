package model

import (
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/kafka"
)

type (
	Config struct {
		App     AppConfig     `yaml:"app"`
		API     APIConfig     `yaml:"api"`
		Adapter AdapterConfig `yaml:"adapter"`
	}

	AppConfig struct {
		Address string `yaml:"address"`
	}

	APIConfig struct {
		APIEnrichment string `yaml:"api_enrichment"`
	}

	AdapterConfig struct {
		Elastic ElasticConfig `yaml:"elastic"`
		Kafka   KafkaConfig   `yaml:"kafka"`
		Resty   RestyConfig   `yaml:"resty"`
	}

	ElasticConfig struct {
		Enrichment elastic.Config `yaml:"enrichment"`
		UDM        elastic.Config `yaml:"udm"`
	}

	KafkaConfig struct {
		Topics    KafkaTopicsConfig    `yaml:"topics"`
		Producers KafkaProducersConfig `yaml:"producers"`
	}

	KafkaTopicsConfig struct {
		CollectEnrichmentTopic string `yaml:"collect_enrichment_topic"`
		CollectEvaluateTopic   string `yaml:"collect_evaluate_topic"`
		DNSCollectTopic        string `yaml:"dns_collect_topic"`
	}

	KafkaProducersConfig struct {
		Enrichment kafka.ProducerConfig `yaml:"enrichment"`
		Evaluate   kafka.ProducerConfig `yaml:"evaluate"`
	}

	RestyConfig struct {
		Timeout int  `yaml:"timeout"`
		Secure  bool `yaml:"secure"`
	}
)
