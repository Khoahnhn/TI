package kafka

import (
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/kafka"
)

type (
	Producer interface {
		Produce(data interface{}, topics ...string) error
		SetProducer(prod kafka.Producer)
	}
)
