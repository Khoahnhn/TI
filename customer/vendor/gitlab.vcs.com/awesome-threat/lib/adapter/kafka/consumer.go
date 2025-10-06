package kafka

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/Shopify/sarama"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"golang.org/x/sync/errgroup"
)

type (
	consumerService struct {
		name    string
		log     pencil.Logger
		client  sarama.ConsumerGroup
		context context.Context
		group   *errgroup.Group
		cancel  func()
	}

	consumerGroup struct {
		log         pencil.Logger
		handlerFunc func(string, []byte, []byte) error
	}
)

func NewConsumer(ctx context.Context, conf ConsumerConfig, handlerFunc func(string, []byte, []byte) error) (Consumer, error) {
	consumer := &consumerService{name: ConsumerModule}
	consumer.log, _ = pencil.New(consumer.name, pencil.DebugLevel, true, os.Stdout)
	// Init
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
	// Prepare Consumer
	conf.Brokers = strings.TrimSpace(conf.Brokers)
	if conf.Brokers == "" {
		return nil, errors.New(ErrBrokersNotFound)
	}
	conf.Topics = strings.TrimSpace(conf.Topics)
	if conf.Topics == "" {
		return nil, errors.New(ErrTopicsNotFound)
	}
	conf.Group = strings.TrimSpace(conf.Group)
	if conf.Group == "" {
		return nil, errors.New(ErrGroupNotFound)
	}
	config.Consumer.Group.Rebalance.Timeout = time.Minute
	config.Consumer.Group.Rebalance.Retry.Max = 10
	config.Consumer.Group.Rebalance.Retry.Backoff = time.Second * 5
	conf.Strategy = strings.TrimSpace(conf.Strategy)
	if conf.Strategy == "" {
		conf.Strategy = sarama.RoundRobinBalanceStrategyName
	}
	switch conf.Strategy {
	case sarama.StickyBalanceStrategyName:
		config.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.BalanceStrategySticky}
	case sarama.RoundRobinBalanceStrategyName:
		config.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.BalanceStrategyRoundRobin}
	case sarama.RangeBalanceStrategyName:
		config.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.BalanceStrategyRange}
	default:
		return nil, errors.New(ErrStrategyInvalid)
	}
	conf.Offset = Offset(strings.TrimSpace(string(conf.Offset)))
	if string(conf.Offset) == "" {
		conf.Offset = OffsetOldest
	}
	switch conf.Offset {
	case OffsetOldest:
		config.Consumer.Offsets.Initial = sarama.OffsetOldest
	case OffsetNewest:
		config.Consumer.Offsets.Initial = sarama.OffsetNewest
	default:
		return nil, errors.New(ErrOffsetInvalid)
	}
	config.Consumer.Offsets.AutoCommit.Enable = true
	config.Consumer.Offsets.AutoCommit.Interval = time.Second
	// Create consumer
	consumer.client, err = sarama.NewConsumerGroup(strings.Split(conf.Brokers, ","), conf.Group, config)
	if err != nil {
		return nil, err
	}
	// Start consumer
	global, cancel := context.WithCancel(ctx)
	consumer.cancel = cancel
	consumer.group, consumer.context = errgroup.WithContext(global)
	cgHandler := &consumerGroup{log: consumer.log, handlerFunc: handlerFunc}
	consumer.group.Go(func() error {
		for {
			if e := consumer.client.Consume(consumer.context, strings.Split(conf.Topics, ","), cgHandler); e != nil {
				consumer.log.Errorf("failed to consume message, error: %v", e)
			}
			if e := consumer.context.Err(); e != nil {
				// Shutdown by context
				return e
			}
		}
	})
	// Receive error
	consumer.group.Go(func() error {
		for {
			select {
			case e := <-consumer.client.Errors():
				consumer.log.Errorf("consumer get a error, error: %v", e)
			case <-consumer.context.Done():
				consumer.cancel = nil
				if err := consumer.client.Close(); err != nil {
					consumer.log.Errorf("failed to close consumer, error: %v", err)
				}
				// Shutdown by context
				return consumer.context.Err()
			}
		}
	})
	// Success
	return consumer, nil
}

func (cs *consumerService) Close() {
	if cs.cancel != nil {
		cs.cancel()
		if err := cs.group.Wait(); err != nil && err != context.Canceled {
			cs.log.Errorf("failed to wait error group, error: %v", err)
		}
	}
}

func (cg *consumerGroup) Setup(session sarama.ConsumerGroupSession) error {
	cg.log.Infof("consumer (%s) - claim (%v)", session.MemberID(), session.Claims())
	// Success
	return nil
}

func (cg *consumerGroup) Cleanup(session sarama.ConsumerGroupSession) error {
	cg.log.Infof("consumer (%s) - cleanup", session.MemberID())
	// Success
	return nil
}

func (cg *consumerGroup) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		if err := cg.handlerFunc(msg.Topic, msg.Key, msg.Value); err != nil {
			cg.log.Errorf("failed to handler message, error: %v", err)
		} else {
			// Mark -> Auto commit
			session.MarkMessage(msg, "")
		}
	}
	// Success
	return nil
}
