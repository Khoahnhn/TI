package kafka

import (
	"context"
	"encoding/json"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/kafka"
)

type producer struct {
	con kafka.Producer
}

func NewProducer(ctx context.Context, conf kafka.ProducerConfig, topics ...string) (Producer, error) {
	if conf.Brokers == "" {
		return &producer{}, nil
	}
	con, err := kafka.NewProducer(ctx, conf)
	if err != nil {
		return nil, err
	}
	// Success
	return &producer{
		con: con,
	}, nil
}

func (inst *producer) Produce(data interface{}, topics ...string) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	for _, topic := range topics {
		if err = inst.con.Produce(topic, "", bytes); err != nil {
			return err
		}
	}
	// Success
	return nil
}

func (inst *producer) SetProducer(prod kafka.Producer) {
	inst.con = prod
}
