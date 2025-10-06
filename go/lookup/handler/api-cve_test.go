package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ws-lookup/defs"
	"ws-lookup/model"
	"ws-lookup/model/mocks"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
)

var (
	MockCVE = &model.CVE{
		Name: "CVE-2014-1234",
	}
)

func TestCVEHandler_LookupMultiple(t *testing.T) {
	testCases := []testCase{
		{
			name: "OK",
			input: testInput{
				"values": []string{"CVE-2024-0101"},
			},
			code: http.StatusOK,
		},
		{
			name: "Invalid CVE",
			input: testInput{
				"values": []string{"ABC-2024-0101"},
			},
			code: http.StatusOK,
		},
		{
			name: "NotFound CVE",
			input: testInput{
				"values": []string{"CVE-2024-0101"},
			},
			code: http.StatusOK,
		},
		{
			name: "InternalServerError Elastic",
			input: testInput{
				"values": []string{"CVE-2024-0101"},
			},
			code: http.StatusInternalServerError,
		},
		{
			name:  "Invalid",
			input: testInput{},
			code:  http.StatusBadRequest,
		},
		{
			name: "TooManyObjects CVE",
			input: testInput{
				"values": []string{"CVE-2024-0101"},
			},
			code: http.StatusBadRequest,
		},
	}
	for _, tCase := range testCases {
		t.Run(tCase.name, func(t *testing.T) {
			testContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			handler := NewCVEHandler(testContext, MockConfig)
			mockCVERepository := mocks.NewMockCVERepository(t)
			handler.Elastic().Enrichment().SetCVERepository(mockCVERepository)

			e := echo.New()
			e.Validator = MockValidator
			if strings.Contains(tCase.name, "TooManyObjects") {
				values := tCase.input["values"].([]string)
				for i := 0; i <= defs.DefaultMaxLookupMultipleLimit; i++ {
					values = append(values, values[0])
				}
				tCase.input["values"] = values
			}
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
				if strings.Contains(tCase.name, "NotFound") {
					mockCVERepository.On("FindByValues", anyArgs(2)...).Return(nil, errors.New(elastic.NotFoundError))
				} else {
					mockCVERepository.On("FindByValues", anyArgs(2)...).Return([]*model.CVE{MockCVE}, nil)
				}
			case http.StatusInternalServerError:
				if strings.Contains(tCase.name, "InternalServerError") {
					mockCVERepository.On("FindByValues", anyArgs(2)...).Return(nil, errors.New("InternalServerError"))
				}
			}
			if assert.NoError(t, handler.LookupMultiple(c)) {
				assert.Equal(t, tCase.code, rec.Code)
			}
		})
	}
}
