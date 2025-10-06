package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"gitlab.viettelcyber.com/awesome-threat/library/adapter/kafka"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type KafkaHandler struct {
	kafka  kafka.Producer
	config model.KafkaConfig
	logger pencil.Logger
}

type ChangeAsset struct {
	EventType  string       `json:"event_type"`
	EventTime  int64        `json:"event_time"`
	EntityId   string       `json:"entity_id"`
	RoutingKey string       `json:"routing_key"`
	Action     string       `json:"action"`
	OldData    *model.Asset `json:"old_data"`
	NewData    *model.Asset `json:"new_data"`
}

func NewKafkaHandler(conf *model.Config) (*KafkaHandler, error) {
	logger, _ = pencil.New("KAFKA_HANDLER", pencil.DebugLevel, true, os.Stdout)
	kafkaProducer, err := kafka.NewProducer(context.Background(), conf.Adapter.Kafka.Producer)
	if err != nil {
		logger.Errorf("NewKafkaHandler-connect to kafka failed: %v", err)
		return nil, err
	}
	return &KafkaHandler{
		kafka:  kafkaProducer,
		logger: logger,
		config: conf.Adapter.Kafka,
	}, nil
}

func (h *KafkaHandler) SendChangeAsset(
	oldAsset *model.Asset,
	newAsset *model.Asset,
	action string,
) error {

	var asset *model.Asset
	if newAsset != nil {
		asset = newAsset
	} else if oldAsset != nil {
		asset = oldAsset
	}
	key := fmt.Sprintf("%s.%s", asset.Organization, asset.ID)
	payload := ChangeAsset{
		EventType:  "asset_updated",
		EventTime:  time.Now().UnixMilli(),
		EntityId:   asset.ID,
		RoutingKey: asset.Type,
		Action:     action,
		OldData:    oldAsset,
		NewData:    newAsset,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	err = h.kafka.Produce(h.config.Topic.TIAssetEvents, key, payloadBytes)
	if err != nil {
		return err
	}
	h.logger.Infof("[SendChangeAsset] success to Topic: %s: %v", h.config.Topic.TIAssetEvents, string(payloadBytes))
	return nil
}
