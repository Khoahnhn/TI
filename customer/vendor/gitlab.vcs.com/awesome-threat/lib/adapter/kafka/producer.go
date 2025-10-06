package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/Shopify/sarama"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
)

type (
	asyncProducerService struct {
		name    string
		log     pencil.Logger
		context context.Context
		client  sarama.AsyncProducer
		cancel  func()
	}

	syncProducerService struct {
		name    string
		log     pencil.Logger
		context context.Context
		client  sarama.SyncProducer
		cancel  func()
	}
)

func NewProducer(ctx context.Context, conf ProducerConfig) (Producer, error) {
	config := sarama.NewConfig()
	version, err := conf.parseVersion()
	if err != nil {
		config.Version = version
	}
	config.Metadata.Full = true
	config.ChannelBufferSize = 2560
	// Prepare Authenticate
	if conf.Auth.Enable {
		config.Net.SASL.Enable = conf.Auth.Enable
		config.Net.SASL.User = conf.Auth.Username
		config.Net.SASL.Password = conf.Auth.Password
		// Algorithm
		conf.Auth.Mechanism = SASLMechanism(strings.TrimSpace(string(conf.Auth.Mechanism)))
		if string(conf.Auth.Mechanism) == "" {
			conf.Auth.Mechanism = SCRAMSHA512
		}
		switch conf.Auth.Mechanism {
		case SCRAMSHA256:
			config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
			config.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: SHA256} }
		case SCRAMSHA512:
			config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
			config.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: SHA512} }
		default:
			return nil, errors.New(ErrMechanismInvalid)
		}
	}
	// Prepare TLS
	if conf.TLS.Enable {
		config.Net.TLS.Enable = conf.TLS.Enable
		config.Net.TLS.Config, err = conf.TLS.createTLSConfiguration()
		if err != nil {
			return nil, err
		}
	}
	// Prepare Producer
	conf.Brokers = strings.TrimSpace(conf.Brokers)
	if conf.Brokers == "" {
		return nil, errors.New(ErrBrokersNotFound)
	}
	config.Producer.Partitioner = sarama.NewHashPartitioner
	config.Producer.Return.Errors = true
	config.Producer.RequiredAcks = sarama.WaitForLocal
	config.Producer.MaxMessageBytes = 1000000
	config.Producer.Timeout = time.Minute
	config.Producer.Retry.Max = 10
	config.Producer.Retry.Backoff = time.Second * 5
	if conf.Async {
		pro, err := sarama.NewAsyncProducer(strings.Split(conf.Brokers, ","), config)
		if err != nil {
			return nil, err
		}
		ps := &asyncProducerService{
			name:   ProducerModule,
			client: pro,
		}
		ps.log, _ = pencil.New(ps.name, pencil.DebugLevel, true, os.Stdout)
		ps.context, ps.cancel = context.WithCancel(ctx)
		// Monitor
		go ps.monitor()
		// Success
		return ps, nil
	} else {
		pro, err := sarama.NewSyncProducer(strings.Split(conf.Brokers, ","), config)
		if err != nil {
			return nil, err
		}
		ps := &syncProducerService{
			name:   ProducerModule,
			client: pro,
		}
		ps.log, _ = pencil.New(ps.name, pencil.DebugLevel, true, os.Stdout)
		ps.context, ps.cancel = context.WithCancel(ctx)
		// Success
		return ps, nil
	}
}

func (p *syncProducerService) Produce(topic string, key interface{}, value interface{}) error {
	msg := &sarama.ProducerMessage{
		Topic: topic,
	}
	switch key.(type) {
	case string:
		if k := key.(string); k != "" {
			msg.Key = sarama.StringEncoder(k)
		}
	case []byte:
		if k := key.([]byte); len(k) > 0 {
			msg.Key = sarama.ByteEncoder(k)
		}
	}
	switch value.(type) {
	case string:
		msg.Value = sarama.StringEncoder(value.(string))
	case []byte:
		msg.Value = sarama.ByteEncoder(value.([]byte))
	}
	if _, _, err := p.client.SendMessage(msg); err != nil {
		return err
	}
	// Success
	return nil
}

func (p *syncProducerService) ProduceObject(topic string, key interface{}, value interface{}, compact bool) error {
	bts, err := json.Marshal(value)
	if err != nil {
		return err
	}
	msg := &sarama.ProducerMessage{
		Topic: topic,
	}
	switch key.(type) {
	case string:
		if k := key.(string); k != "" {
			msg.Key = sarama.StringEncoder(k)
		}
	case []byte:
		if k := key.([]byte); len(k) > 0 {
			msg.Key = sarama.ByteEncoder(k)
		}
	}
	if compact {
		msg.Value = sarama.ByteEncoder(bts)
	} else {
		jsonStr := string(bts)
		msg.Value = sarama.StringEncoder(jsonStr)
	}
	if _, _, err = p.client.SendMessage(msg); err != nil {
		return err
	}
	// Success
	return nil
}

func (p *syncProducerService) Close() {
	// Success
	if err := p.client.Close(); err != nil {
		p.log.Errorf("failed to close sync producer, error: %v", err)
	}
}

func (p *asyncProducerService) Produce(topic string, key interface{}, value interface{}) error {
	msg := &sarama.ProducerMessage{
		Topic: topic,
	}
	switch key.(type) {
	case string:
		if k := key.(string); k != "" {
			msg.Key = sarama.StringEncoder(k)
		}
	case []byte:
		if k := key.([]byte); len(k) > 0 {
			msg.Key = sarama.ByteEncoder(k)
		}
	}
	switch value.(type) {
	case string:
		msg.Value = sarama.StringEncoder(value.(string))
	case []byte:
		msg.Value = sarama.ByteEncoder(value.([]byte))
	}
	p.client.Input() <- msg
	// Success
	return nil
}

func (p *asyncProducerService) ProduceObject(topic string, key interface{}, value interface{}, compact bool) error {
	bts, err := json.Marshal(value)
	if err != nil {
		return err
	}
	msg := &sarama.ProducerMessage{
		Topic: topic,
	}
	switch key.(type) {
	case string:
		if k := key.(string); k != "" {
			msg.Key = sarama.StringEncoder(k)
		}
	case []byte:
		if k := key.([]byte); len(k) > 0 {
			msg.Key = sarama.ByteEncoder(k)
		}
	}
	if compact {
		msg.Value = sarama.ByteEncoder(bts)
	} else {
		jsonStr := string(bts)
		msg.Value = sarama.StringEncoder(jsonStr)
	}
	p.client.Input() <- msg
	// Success
	return nil
}

func (p *asyncProducerService) Close() {
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *asyncProducerService) monitor() {
	for {
		select {
		case err := <-p.client.Errors():
			if err != nil {
				bts, e := err.Msg.Value.Encode()
				if e != nil {
					p.log.Errorf("failed to get error message, error: %v", err)
					continue
				}
				p.log.Errorf("failed to produce message, error: %v, document: %s", err, string(bts))
			}
		case <-p.context.Done():
			p.log.Info("close async producer")
			if err := p.client.Close(); err != nil {
				p.log.Errorf("failed to close async producer, error: %v", err)
			}
			return
		}
	}
}
