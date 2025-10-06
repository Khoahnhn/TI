
## kafka (sarama)

### Config

Kafka config:

```
ProducerConfig struct {
    Config
    Async bool `json:"async" yaml:"async"`  # default: false
}

ConsumerConfig struct {
    Config
    Topics   string `json:"topics" yaml:"topics"`
    Group    string `json:"group" yaml:"group"`
    Strategy string `json:"strategy" yaml:"strategy"`   # default: roundrobin
    Offset   Offset `json:"offset" yaml:"offset"`       # default: oldest (option: oldest, latest)
}

Config struct {
    Brokers string     `json:"brokers" yaml:"brokers"`
    Auth    AuthConfig `json:"auth" yaml:"auth"`
    TLS     TLSConfig  `json:"tls" yaml:"tls"`
    Version string     `json:"version" yaml:"version"`
}

AuthConfig struct {
    Enable    bool          `json:"enable" yaml:"enable"`
    Mechanism SASLMechanism `json:"mechanism" yaml:"mechanism"`     # default: sha256 (option: sha256, sha512)
    Username  string        `json:"username" yaml:"username"`
    Password  string        `json:"password" yaml:"password"`
}

TLSConfig struct {
    Enable             bool   `json:"enable" yaml:"enable"`
    InsecureSkipVerify bool   `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
    CertFile           string `json:"cert_file" yaml:"cert_file"`
    KeyFile            string `json:"key_file" yaml:"key_file"`
    CAFile             string `json:"ca_file" yaml:"ca_file"`
}
```

### Producer

- Create Producer:

```
kafka.NewProducer(ctx context.Context, conf kafka.ProducerConfig) (kafka.Producer, error)
```

- Function:
```
# Produce a message
Produce(topic, key string, value []byte) error
# Close producer
Close()                        
```

### Consumer

Config:

- Create Consumer:

```
kafka.NewConsumer(ctx context.Context, conf kafka.ConsumerConfig, handlerFunc func(string, []byte, []byte) error) (kafka.Consumer, error)
```

- Function:
```
# Close consumer
Close()
```