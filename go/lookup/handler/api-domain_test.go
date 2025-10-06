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
	MockDomainPassiveDNS = udm.PassiveDNSDomain{
		PassiveDNS: udm.PassiveDNS{
			ResolutionTime: 1,
			IPAddress:      "8.8.8.8",
		},
	}
	MockDNSRecord = udm.DNSRecord{
		A:     make([]string, 0),
		AAAA:  make([]string, 0),
		CName: make([]string, 0),
		MX:    make([]string, 0),
		TXT:   make([]string, 0),
		NS:    make([]string, 0),
	}
	MockSubdomain = udm.Subdomain{
		FullDomain:  "example.example.com",
		RootDomain:  "example.com",
		ResolveTime: 1,
		IPAddress:   "8.8.8.8",
	}
	MockSiblingDomain = udm.SiblingDomain{
		FullDomain:  "example.example.com",
		RootDomain:  "example.com",
		ResolveTime: 1,
		IPAddress:   "8.8.8.8",
	}
)

func TestDomainLookup(t *testing.T) {
	testCases := []testCase{
		{
			name: "OK",
			input: testInput{
				"value": "example.com",
				"sections": map[string]*model.RequestSection{
					defs.SectionPopularityRank: {Limit: 10},
					defs.SectionWhois:          {Limit: 10},
					defs.SectionPassiveDNS:     {},
					defs.SectionDNSRecord:      {},
					defs.SectionHash:           {},
					defs.SectionSubdomains:     {},
					defs.SectionSiblings:       {},
					defs.SectionSSLCertificate: {Limit: 10},
					defs.SectionRelations:      {},
					defs.SectionSecurityResult: {},
				},
			},
			code: http.StatusOK,
		},
		{
			name: "BadRequest",
			input: testInput{
				"value": "invalid_domain",
			},
			code: http.StatusBadRequest,
		},
		{
			name: "InternalServerError",
			input: testInput{
				"value": "example.com",
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

			handler := NewDomainHandler(testContext, MockConfig)
			mockDbUDM := mocks.NewMockUDMRepository(t)
			handler.Elastic().UDM().Object().SetDbCon(mockDbUDM)
			mockKafkaProducer := mocks.NewMockKafkaProducer(t)
			handler.(*DomainHandler).producerEnrich.SetProducer(mockKafkaProducer)
			handler.(*DomainHandler).producerEvaluate.SetProducer(mockKafkaProducer)
			mockResty := mocks.NewMockRestyClient(t)
			handler.(*DomainHandler).client = mockResty

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
				mockResty.On("GetDomainPassiveDNS", anyArgs(5)...).Run(func(args mock.Arguments) {
					docPtr := args.Get(4).(*model.ResponseEnrichmentPassiveDNSDomain)
					*docPtr = model.ResponseEnrichmentPassiveDNSDomain{
						Detail: &udm.ResponseEnrichmentPassiveDNSDomain{
							Data:  []*udm.PassiveDNSDomain{&MockDomainPassiveDNS},
							Total: 1,
						},
					}
				}).Return(MockRestyResponse(http.StatusOK), nil)
				mockResty.On("GetSubdomains", anyArgs(5)...).Run(func(args mock.Arguments) {
					docPtr := args.Get(4).(*model.ResponseEnrichmentSubdomain)
					*docPtr = model.ResponseEnrichmentSubdomain{
						Detail: &udm.ResponseEnrichmentSubdomain{
							Data:  []*udm.Subdomain{&MockSubdomain},
							Total: 1,
						},
					}
				}).Return(MockRestyResponse(http.StatusOK), nil).Once()
				mockResty.On("GetSiblingDomains", anyArgs(5)...).Run(func(args mock.Arguments) {
					docPtr := args.Get(4).(*model.ResponseEnrichmentSibling)
					*docPtr = model.ResponseEnrichmentSibling{
						Detail: &udm.ResponseEnrichmentSiblingDomain{
							Data:  []*udm.SiblingDomain{&MockSiblingDomain},
							Total: 1,
						},
					}
				}).Return(MockRestyResponse(http.StatusOK), nil).Once()
			case http.StatusInternalServerError:
				mockDbUDM.On("Get", anyArgs(3)...).Return(nil, ErrMock).Once()
			}

			if assert.NoError(t, handler.Lookup(c)) {
				assert.Equal(t, tCase.code, rec.Code)
			}
		})
	}
}

func TestDomainLookupMultiple(t *testing.T) {
	testCases := []testCase{
		{
			name: "OK",
			input: testInput{
				"values": []string{"example.com", "testDomain"},
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

			handler := NewDomainHandler(testContext, MockConfig)
			mockDbUDM := mocks.NewMockUDMRepository(t)
			handler.Elastic().UDM().Object().SetDbCon(mockDbUDM)
			mockKafkaProducer := mocks.NewMockKafkaProducer(t)
			handler.(*DomainHandler).producerEnrich.SetProducer(mockKafkaProducer)
			handler.(*DomainHandler).producerEvaluate.SetProducer(mockKafkaProducer)

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
