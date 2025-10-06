package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"ws-lookup/defs"
	"ws-lookup/model"
	"ws-lookup/model/mocks"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

var (
	MockIPAddressPassiveDNS = udm.PassiveDNSIPAddress{
		PassiveDNS: udm.PassiveDNS{
			ResolutionTime: 1,
			Domain:         "example.com",
		},
	}
	MockIP = udm.IP{
		IP: "8.8.8.8",
	}
)

func TestIPAddressLookup(t *testing.T) {
	testCases := []testCase{
		{
			name: "OK",
			input: testInput{
				"value": "8.8.8.8",
				"sections": map[string]*model.RequestSection{
					defs.SectionArtifact:       {Limit: 10},
					defs.SectionPassiveDNS:     {},
					defs.SectionHash:           {},
					defs.SectionSubnet:         {},
					defs.SectionRelations:      {},
					defs.SectionSecurityResult: {},
				},
			},
			code: http.StatusOK,
		},
		{
			name: "BadRequest",
			input: testInput{
				"value": "invalid_ip_address",
			},
			code: http.StatusBadRequest,
		},
		{
			name: "InternalServerError",
			input: testInput{
				"value": "8.8.8.8",
			},
			code: http.StatusInternalServerError,
		},
	}

	for _, tCase := range testCases {
		t.Run(tCase.name, func(t *testing.T) {
			os.Setenv(defs.EnvTldCachePath, "../tld.cache")
			defer os.Unsetenv(defs.EnvTldCachePath)
			testContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			handler := NewIPAddressHandler(testContext, MockConfig)
			mockDbUDM := mocks.NewMockUDMRepository(t)
			handler.Elastic().UDM().Object().SetDbCon(mockDbUDM)
			mockKafkaProducer := mocks.NewMockKafkaProducer(t)
			handler.(*IPAddressHandler).producerEnrich.SetProducer(mockKafkaProducer)
			handler.(*IPAddressHandler).producerEvaluate.SetProducer(mockKafkaProducer)
			mockResty := mocks.NewMockRestyClient(t)
			handler.(*IPAddressHandler).client = mockResty

			e := echo.New()
			e.Validator = MockValidator
			jsonInput, err := json.Marshal(tCase.input)
			if err != nil {
				t.Fatalf("json marshal error: %v\n", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(jsonInput))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			switch tCase.code {
			case http.StatusOK:
				mockDbUDM.On("Get", anyArgs(3)...).Return(nil, nil).Once()
				mockDbUDM.On("InsertOne", anyArgs(3)...).Return(nil).Once()
				mockKafkaProducer.On("Produce", anyArgs(3)...).Return(nil).Maybe()
				mockDbUDM.On("Get", anyArgs(3)...).Return(MockEntity, nil)
				mockDbUDM.On("GetTargetRelationships", anyArgs(7)...).Return([]*udm.Entity{MockEntity}, nil)
				mockDbUDM.On("CountTargetRelationships", anyArgs(3)...).Return(int64(0), nil)
				mockResty.On("GetIPAddressPassiveDNS", anyArgs(5)...).Run(func(args mock.Arguments) {
					docPtr := args.Get(4).(*model.ResponseEnrichmentPassiveDNSIPAddress)
					*docPtr = model.ResponseEnrichmentPassiveDNSIPAddress{
						Detail: &udm.ResponseEnrichmentPassiveDNSIPAddress{
							Data:  []*udm.PassiveDNSIPAddress{&MockIPAddressPassiveDNS},
							Total: 1,
						},
					}
				}).Return(MockRestyResponse(http.StatusOK), nil)
				mockResty.On("GetSubnet", anyArgs(5)...).Run(func(args mock.Arguments) {
					docPtr := args.Get(4).(*model.ResponseEnrichmentSubnet)
					*docPtr = model.ResponseEnrichmentSubnet{
						Detail: &udm.ResponseEnrichmentSubnet{
							Data:  []*udm.PassiveDNSIPAddress{&MockIPAddressPassiveDNS},
							Total: 1,
						},
					}
				}).Return(MockRestyResponse(http.StatusOK), nil)
			case http.StatusInternalServerError:
				mockDbUDM.On("Get", anyArgs(3)...).Return(nil, ErrMock).Once()
			}

			if assert.NoError(t, handler.Lookup(c)) {
				assert.Equal(t, tCase.code, rec.Code)
			}
		})
	}
}

func TestIPAddressLookupMultiple(t *testing.T) {
	testCases := []testCase{
		{
			name: "OK",
			input: testInput{
				"values": []string{"8.8.8.8", "testIP"},
			},
			code: http.StatusOK,
		},
		{
			name:  "BadRequest",
			input: testInput{},
			code:  http.StatusBadRequest,
		},
	}

	for _, tCase := range testCases {
		t.Run(tCase.name, func(t *testing.T) {
			os.Setenv(defs.EnvTldCachePath, "../tld.cache")
			defer os.Unsetenv(defs.EnvTldCachePath)
			testContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			handler := NewIPAddressHandler(testContext, MockConfig)
			mockDbUDM := mocks.NewMockUDMRepository(t)
			handler.Elastic().UDM().Object().SetDbCon(mockDbUDM)
			mockKafkaProducer := mocks.NewMockKafkaProducer(t)
			handler.(*IPAddressHandler).producerEnrich.SetProducer(mockKafkaProducer)
			handler.(*IPAddressHandler).producerEvaluate.SetProducer(mockKafkaProducer)

			e := echo.New()
			e.Validator = MockValidator
			jsonInput, err := json.Marshal(tCase.input)
			if err != nil {
				t.Fatalf("json marshal error: %v\n", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(jsonInput))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			switch tCase.code {
			case http.StatusOK:
				mockDbUDM.On("Get", anyArgs(3)...).Return(nil, nil)
				mockDbUDM.On("InsertOne", anyArgs(3)...).Return(nil)
				mockKafkaProducer.On("Produce", anyArgs(3)...).Return(nil).Maybe()
				mockDbUDM.On("GetTargetRelationships", anyArgs(7)...).Return([]*udm.Entity{MockEntity}, nil)
				mockDbUDM.On("CountTargetRelationships", anyArgs(4)...).Return(int64(1), nil)
			}

			if assert.NoError(t, handler.LookupMultiple(c)) {
				assert.Equal(t, tCase.code, rec.Code)
			}
		})
	}
}
