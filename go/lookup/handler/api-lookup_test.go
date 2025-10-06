package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"ws-lookup/defs"
	"ws-lookup/model/mocks"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

var (
	MockDomain         = udm.Domain{}
	MockURL            = udm.URL{}
	MockPopularityRank = udm.PopularityRank{}
	MockWhois          = udm.Whois{}
	MockArtifact       = udm.Artifact{}
	MockRelationship   = udm.Relationship{}
	MockSecurityResult = udm.SecurityResult{}
	MockSSLCertificate = udm.SSLCertificate{}
)

var (
	MockEntity = &udm.Entity{
		Metadata: udm.Metadata{
			ValidToTimestamp: 0,
		},
		Noun: udm.Noun{
			GeneralNoun: udm.GeneralNoun{
				Domain: &MockDomain,
				IP:     &MockIP,
				URL:    &MockURL,
			},
			PopularityRank: &MockPopularityRank,
			Whois:          &MockWhois,
			Artifact:       &MockArtifact,
			DNSRecord:      &MockDNSRecord,
			SSLCertificate: &MockSSLCertificate,
			Relationship:   &MockRelationship,
			SecurityResult: &MockSecurityResult,
		},
	}
)

func TestLookup(t *testing.T) {
	testCases := []testCase{
		{
			name:  "OK_NoObject_Domain",
			input: testInput{"value": "example.com", "entity_type": udm.EntityTypeDomain},
			code:  http.StatusOK,
		},
		{
			name:  "OK_NoObject_IP",
			input: testInput{"value": "8.8.8.8", "entity_type": udm.EntityTypeIPAddress},
			code:  http.StatusOK,
		},
		{
			name:  "OK_NoObject_URL",
			input: testInput{"value": "http://example.com", "entity_type": udm.EntityTypeURL},
			code:  http.StatusOK,
		},
		// {
		// 	name:  "OK_NoObject_File_MD5",
		// 	input: testInput{"value": hash.MD5("test"), "entity_type": udm.EntityTypeFile},
		// 	code:  http.StatusOK,
		// },
		// {
		// 	name:  "OK_NoObject_File_SHA1",
		// 	input: testInput{"value": hash.SHA1("test"), "entity_type": udm.EntityTypeFile},
		// 	code:  http.StatusOK,
		// },
		// {
		// 	name:  "OK_NoObject_File_SHA256",
		// 	input: testInput{"value": hash.SHA256("test"), "entity_type": udm.EntityTypeFile},
		// 	code:  http.StatusOK,
		// },
		{
			name:  "OK_Stored_Domain",
			input: testInput{"value": "example.com", "entity_type": udm.EntityTypeDomain},
			code:  http.StatusOK,
		},
		{
			name:  "OK_Stored_IPAddress",
			input: testInput{"value": "8.8.8.8", "entity_type": udm.EntityTypeIPAddress},
			code:  http.StatusOK,
		},
		{
			name:  "OK_Stored_URL",
			input: testInput{"value": "http://example.com", "entity_type": udm.EntityTypeURL},
			code:  http.StatusOK,
		},
		{
			name:  "OK_Queried_Domain",
			input: testInput{"value": "example.com", "entity_type": udm.EntityTypeDomain},
			code:  http.StatusOK,
		},
		{
			name:  "OK_Queried_IPAddress",
			input: testInput{"value": "8.8.8.8", "entity_type": udm.EntityTypeIPAddress},
			code:  http.StatusOK,
		},
		{
			name:  "OK_Queried_URL",
			input: testInput{"value": "http://example.com", "entity_type": udm.EntityTypeURL},
			code:  http.StatusOK,
		},
		{
			name:  "OK_InferredEntityType",
			input: testInput{"value": "test_value"},
			code:  http.StatusOK,
		},
		{
			name:  "BadRequest_NoValue",
			input: testInput{},
			code:  http.StatusBadRequest,
		},
		{
			name:  "BadRequest_InvalidDomain",
			input: testInput{"value": "invalid_domain", "entity_type": udm.EntityTypeDomain},
			code:  http.StatusBadRequest,
		},
		{
			name:  "BadRequest_InvalidIPAddress",
			input: testInput{"value": "invalid_ip", "entity_type": udm.EntityTypeIPAddress},
			code:  http.StatusBadRequest,
		},
		{
			name:  "BadRequest_InvalidURL",
			input: testInput{"value": "invalid_url", "entity_type": udm.EntityTypeURL},
			code:  http.StatusBadRequest,
		},
		{
			name:  "BadRequest_InvalidSample",
			input: testInput{"value": "invalid_sample", "entity_type": udm.EntityTypeFile},
			code:  http.StatusBadRequest,
		},
		{
			name:  "BadRequest_InvalidEntityType",
			input: testInput{"value": "test_value", "entity_type": "invalid_type"},
			code:  http.StatusBadRequest,
		},
		{
			name:  "BadRequest_InvalidSection",
			input: testInput{"value": "example.com", "entity_type": udm.EntityTypeDomain, "sections": []string{"invalid_section"}},
			code:  http.StatusBadRequest,
		},
		{
			name:  "NotFound",
			input: testInput{"value": "test_value"},
			code:  http.StatusNotFound,
		},
		{
			name:  "InternalServerError",
			input: testInput{"value": "example.com", "entity_type": udm.EntityTypeDomain},
			code:  http.StatusInternalServerError,
		},
	}

	for _, tCase := range testCases {
		t.Run(tCase.name, func(t *testing.T) {
			os.Setenv(defs.EnvTldCachePath, "../tld.cache")
			defer os.Unsetenv(defs.EnvTldCachePath)
			testContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			handler := NewLookupHandler(testContext, MockConfig)
			mockDbUDM := mocks.NewMockUDMRepository(t)
			handler.Elastic().UDM().Object().SetDbCon(mockDbUDM)
			mockKafkaProducer := mocks.NewMockKafkaProducer(t)
			handler.(*LookupHandler).producerEnrich.SetProducer(mockKafkaProducer)
			handler.(*LookupHandler).producerEvaluate.SetProducer(mockKafkaProducer)
			mockResty := mocks.NewMockRestyClient(t)
			handler.(*LookupHandler).client = mockResty
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
				if strings.Contains(tCase.name, "NoObject") {
					mockDbUDM.On("Get", anyArgs(3)...).Return(nil, errors.New(defs.ErrNotFound)).Once()
					mockDbUDM.On("InsertOne", anyArgs(3)...).Return(nil).Once()
					mockKafkaProducer.On("Produce", anyArgs(3)...).Return(nil).Maybe()
					mockDbUDM.On("CountTargetRelationships", anyArgs(3)...).Return(int64(0), nil)
					mockDbUDM.On("GetTargetRelationships", anyArgs(7)...).Return(nil, errors.New(defs.ErrNotFound))
				} else if strings.Contains(tCase.name, "Stored") {
					mockDbUDM.On("Get", anyArgs(3)...).Return(MockEntity, nil)
					mockDbUDM.On("CountTargetRelationships", anyArgs(3)...).Return(int64(0), nil)
					mockKafkaProducer.On("Produce", anyArgs(3)...).Return(nil).Maybe()
					mockDbUDM.On("GetTargetRelationships", anyArgs(7)...).Return([]*udm.Entity{MockEntity}, nil)
				} else if strings.Contains(tCase.name, "Queried") {
					mockDbUDM.On("Get", anyArgs(3)...).Return(MockEntity, nil)
					mockDbUDM.On("CountTargetRelationships", anyArgs(3)...).Return(int64(0), nil)
					mockDbUDM.On("GetTargetRelationships", anyArgs(7)...).Return(nil, errors.New(defs.ErrNotFound))
					mockKafkaProducer.On("Produce", anyArgs(3)...).Return(nil).Maybe()
				} else if strings.Contains(tCase.name, "InferredEntityType") {
					mockDbUDM.On("FindAll", anyArgs(4)...).Return([]*udm.Entity{udm.NewEntity("test_value", udm.EntityTypeDomain)}, nil)
					mockDbUDM.On("Get", anyArgs(3)...).Return(MockEntity, nil)
					mockKafkaProducer.On("Produce", anyArgs(3)...).Return(nil).Maybe()
					mockDbUDM.On("CountTargetRelationships", anyArgs(3)...).Return(int64(0), nil)
					mockDbUDM.On("GetTargetRelationships", anyArgs(7)...).Return([]*udm.Entity{MockEntity}, nil)
				}
			case http.StatusNotFound:
				mockDbUDM.On("FindAll", anyArgs(4)...).Return([]*udm.Entity{}, nil)
			case http.StatusInternalServerError:
				mockDbUDM.On("Get", anyArgs(3)...).Return(nil, ErrMock).Once()
			}

			if assert.NoError(t, handler.Lookup(c)) {
				assert.Equal(t, tCase.code, rec.Code)
			}
		})
	}
}

func TestIdentify(t *testing.T) {
	testCases := []testCase{
		{
			name:  "OK",
			input: testInput{"values": []string{"example.com", "8.8.8.8", hash.SHA1("test"), "CVE-1111-1111"}},
			code:  http.StatusOK,
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
			testContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			handler := NewLookupHandler(testContext, MockConfig)
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

			if assert.NoError(t, handler.Identify(c)) {
				assert.Equal(t, tCase.code, rec.Code)
			}
		})
	}
}
