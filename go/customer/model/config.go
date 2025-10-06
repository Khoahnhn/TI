package model

import (
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/kafka"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/rabbit"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/redis"
)

type (
	Config struct {
		App     AppConfig     `yaml:"app"`
		Api     ApiConfig     `yaml:"api"`
		Adapter AdapterConfig `yaml:"adapter"`
		Mail    MailConfig    `yaml:"mail"`
	}

	MailConfig struct {
		BaseURL         string            `yaml:"base_url"`
		PortalPublicURL string            `yaml:"portal_public_url"`
		BasePage        string            `yaml:"base_page"`
		PhoneContact    string            `yaml:"phone_contact"`
		SaleContact     string            `yaml:"sale_contact"`
		SaleContact1    string            `yaml:"sale_contact_1"`
		URLLogin        string            `yaml:"url_login"`
		UserGuide       map[string]string `yaml:"user_guide"`
		LinkPackage     string            `yaml:"link_package"`
		TemplatePath    string            `yaml:"template_path"`
		MailAPI         string            `yaml:"mail_api"`
		ReceiverMailDev []string          `yaml:"receiver_mail_dev"`

		Proxy string `yaml:"proxy"`
	}

	AppConfig struct {
		Address               string `yaml:"address"`
		Secret                string `yaml:"secret"`
		SyncAssetMappingIndex bool   `yaml:"sync_asset_mapping_index"`
		Mode                  string `yaml:"mode"`
	}

	ApiConfig struct {
		Threat string `json:"threat"`
		OpV1   string `json:"opv1"`
	}

	AdapterConfig struct {
		Mongo   MongoConfig   `yaml:"mongo"`
		Elastic ElasticConfig `yaml:"elastic"`
		Rabbit  RabbitConfig  `yaml:"rabbit"`
		Kafka   KafkaConfig   `yaml:"kafka"`
		Redis   RedisConfig   `yaml:"redis"`
	}

	MongoConfig struct {
		Account  mongo.Config        `yaml:"account"`
		Settings mongo.Config        `yaml:"settings"`
		Database MongoDatabaseConfig `yaml:"database"`
	}

	MongoDatabaseConfig struct {
		TIAccount string `yaml:"ti_account"`
		Settings  string `yaml:"settings"`
	}

	ElasticConfig struct {
		Enduser elastic.Config     `yaml:"enduser"`
		Index   ElasticIndexConfig `yaml:"index"`
	}

	ElasticIndexConfig struct {
		TIAsset        string `yaml:"ti_asset"`
		TIAssetHistory string `yaml:"ti_asset_history"`
	}

	RabbitConfig struct {
		Crawler rabbit.Config `yaml:"crawler"`
	}

	RedisConfig struct {
		Cache redis.Config `yaml:"cache"`
	}

	KafkaConfig struct {
		Producer kafka.ProducerConfig `yaml:"producer"`
		Topic    KafkaTopicConfig     `yaml:"topic"`
	}

	KafkaTopicConfig struct {
		TIAssetEvents string `yaml:"ti_asset_events"`
	}
)
