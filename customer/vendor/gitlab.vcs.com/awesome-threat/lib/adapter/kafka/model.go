package kafka

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/Shopify/sarama"
)

type (
	ProducerConfig struct {
		Config `yaml:",inline" mapstructure:",squash"`
		Async  bool `json:"async" yaml:"async" mapstructure:"async"`
	}

	ConsumerConfig struct {
		Config   `yaml:",inline" mapstructure:",squash"`
		Topics   string `json:"topics" yaml:"topics" mapstructure:"topics"`
		Group    string `json:"group" yaml:"group" mapstructure:"group"`
		Strategy string `json:"strategy" yaml:"strategy" mapstructure:"strategy"`
		Offset   Offset `json:"offset" yaml:"offset" mapstructure:"offset"`
	}

	Config struct {
		Brokers string     `json:"brokers" yaml:"brokers" mapstructure:"brokers"`
		Auth    AuthConfig `json:"auth" yaml:"auth" mapstructure:"auth"`
		TLS     TLSConfig  `json:"tls" yaml:"tls" mapstructure:"tls"`
		Version string     `json:"version" yaml:"version" mapstructure:"version"`
	}

	AuthConfig struct {
		Enable    bool          `json:"enable" yaml:"enable" mapstructure:"enable"`
		Mechanism SASLMechanism `json:"mechanism" yaml:"mechanism" mapstructure:"mechanism"`
		Username  string        `json:"username" yaml:"username" mapstructure:"username"`
		Password  string        `json:"password" yaml:"password" mapstructure:"password"`
	}

	TLSConfig struct {
		Enable             bool   `json:"enable" yaml:"enable" mapstructure:"enable"`
		InsecureSkipVerify bool   `json:"insecure_skip_verify" yaml:"insecure_skip_verify" mapstructure:"insecure_skip_verify"`
		CertFile           string `json:"cert_file" yaml:"cert_file" mapstructure:"cert_file"`
		KeyFile            string `json:"key_file" yaml:"key_file" mapstructure:"key_file"`
		CAFile             string `json:"ca_file" yaml:"ca_file" mapstructure:"ca_file"`
	}

	Offset        string
	SASLMechanism string
)

func (conf Config) parseVersion() (sarama.KafkaVersion, error) {
	// Success
	return sarama.ParseKafkaVersion(conf.Version)
}

func (conf TLSConfig) createTLSConfiguration() (*tls.Config, error) {
	if !conf.Enable {
		return nil, nil
	}
	t := &tls.Config{
		InsecureSkipVerify: conf.InsecureSkipVerify,
	}
	if conf.CertFile != "" && conf.KeyFile != "" && conf.CAFile != "" {
		cert, err := tls.LoadX509KeyPair(conf.CertFile, conf.KeyFile)
		if err != nil {
			return nil, err
		}
		caCert, err := os.ReadFile(conf.CAFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		t.Certificates = []tls.Certificate{cert}
		t.RootCAs = caCertPool
	}
	// Success
	return t, nil
}
