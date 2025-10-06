package handler

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"ws-lookup/defs"
	"ws-lookup/model"

	"github.com/go-playground/validator/v10"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/mock"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
)

var (
	MockConfig = model.Config{
		Adapter: model.AdapterConfig{
			Kafka: model.KafkaConfig{
				Topics: model.KafkaTopicsConfig{
					CollectEnrichmentTopic: "test-topic",
					CollectEvaluateTopic:   "test-topic",
				}},
			Elastic: model.ElasticConfig{
				Enrichment: elastic.Config{
					Address: "http://localhost:9211",
				},
				UDM: elastic.Config{
					Address: "http://localhost:9220",
				},
			},
		},
	}
	MockValidator = &CustomValidator{validator: validator.New()}
	ErrMock       = errors.New("test error")
)

type (
	testInput map[string]interface{}
	testCase  struct {
		name  string
		input testInput
		code  int
	}
)

func anyArgs(count int) []interface{} {
	args := make([]interface{}, count)
	for i := range args {
		args[i] = mock.Anything
	}
	return args
}

func MockRestyResponse(code int) *resty.Response {
	return &resty.Response{
		RawResponse: &http.Response{
			Status:     http.StatusText(code),
			StatusCode: code,
		},
	}
}

func TestAPIHandlerStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	os.Setenv(defs.EnvTldCachePath, "../tld.cache")
	defer os.Unsetenv(defs.EnvTldCachePath)
	APIHandlerStart(ctx, &MockConfig)
}
