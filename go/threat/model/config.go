package model

import (
	es "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/kafka"
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	rb "gitlab.viettelcyber.com/awesome-threat/library/adapter/rabbit"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/redis"
)

type (
	Config struct {
		App       AppConfig       `yaml:"app"`
		Api       ApiConfig       `yaml:"api"`
		Connector ConnectorConfig `yaml:"connector"`
	}

	AppConfig struct {
		Debug         bool          `yaml:"debug"`
		Address       string        `yaml:"address"`
		Core          int           `yaml:"core"`
		Predict       PredictConfig `yaml:"predict"`
		MaxSizeExport int           `yaml:"max_size_export"`
		APIKey        string        `yaml:"apikey"`
	}

	PredictConfig struct {
		TrustedAVs  []string `yaml:"trusted_avs"`
		ThresholdAV int      `yaml:"threshold_av"`
	}

	ApiConfig struct {
		Timeout    int              `yaml:"timeout"`
		Route      RouteConfig      `yaml:"route"`
		Credential CredentialConfig `yaml:"credential"`
	}

	RouteConfig struct {
		Enrichment string `yaml:"enrichment"`
		Export     string `yaml:"export"`
		Mail       string `yaml:"mail"`
		Customer   string `yaml:"customer"`
		APIGroup   string `yaml:"api_group"`
	}

	CredentialConfig struct {
		Enrichment AuthConfig `yaml:"enrichment"`
		Export     AuthConfig `yaml:"export"`
	}

	AuthConfig struct {
		Enable   bool   `yaml:"enable"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		APIKey   string `yaml:"apikey"`
	}

	ConnectorConfig struct {
		Mongo   MongoConfig   `yaml:"mongo"`
		Elastic ElasticConfig `yaml:"elastic"`
		Rabbit  RabbitConfig  `yaml:"rabbit"`
		Redis   RedisConfig   `yaml:"redis"`
		Kafka   KafkaConfig   `yaml:"kafka"`
	}

	MongoConfig struct {
		Account      mg.Config `yaml:"account"`
		Enduser      mg.Config `yaml:"enduser"`
		ThreatReport mg.Config `yaml:"threat_report"`
	}

	ElasticConfig struct {
		Enduser    es.Config `yaml:"enduser"`
		Enrichment es.Config `yaml:"enrichment"`
	}

	RabbitConfig struct {
		Crawler rb.Config `yaml:"crawler"`
	}

	RedisConfig struct {
		General redis.Config `json:"general" yaml:"general"`
	}

	KafkaConfig struct {
		Topics    KafkaTopicsConfig    `yaml:"topics"`
		Producers KafkaProducersConfig `yaml:"producers"`
	}

	KafkaTopicsConfig struct {
		UDMEnrichmentTopic string `yaml:"udm_enrichment_topic"`
		UDMEvaluateTopic   string `yaml:"udm_evaluate_topic"`
		TAXIISyncTopic     string `yaml:"taxii_sync_topic"`
	}

	KafkaProducersConfig struct {
		Enrichment kafka.ProducerConfig `yaml:"enrichment"`
		Evaluate   kafka.ProducerConfig `yaml:"evaluate"`
		ThreatFeed kafka.ProducerConfig `yaml:"threat_feed"`
	}
)
