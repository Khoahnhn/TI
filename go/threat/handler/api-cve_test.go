package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang/mock/gomock"
	es "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	mocks "gitlab.viettelcyber.com/ti-micro/ws-threat/mocks/repo/elastic"
	mockmg "gitlab.viettelcyber.com/ti-micro/ws-threat/mocks/repo/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type customValidator struct{}

func (v *customValidator) Validate(i interface{}) error {
	return nil
}

type mockValidator struct{}

func (v *mockValidator) Validate(i interface{}) error {
	return errors.New("validation failed")
}

func TestCVEHandler_verifyLifeCycleCVE(t *testing.T) {
	tests := []struct {
		name            string
		requestBody     string
		expectError     bool
		customValidator echo.Validator
	}{
		{
			name:        "Invalid JSON (Bind Error)",
			requestBody: `{invalid json}`,
			expectError: true,
		},
		{
			name: "Validation Error",
			requestBody: `{
				"report_code": "R1",
				"cve_code": ["CVE-2024-1234"],
				"detection_time": 1710000000000
			}`,
			expectError:     true,
			customValidator: &mockValidator{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			if tt.customValidator != nil {
				e.Validator = tt.customValidator
			}
			req := httptest.NewRequest(http.MethodPost, "/lifecycle-cve", strings.NewReader(tt.requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			h := &CVEHandler{}
			_, err := h.verifyLifeCycleCVE(c)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCVEHandler_PrepareQuery(t *testing.T) {
	req := &model.RequestLifeCycleCVE{
		CVECode: []string{"cve-1", "cve-2"},
	}
	got := req.PrepareQuery()

	expected := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"terms": map[string]interface{}{
						"name": []string{"cve-1", "cve-2"},
					},
				},
			},
		},
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("PrepareQuery() = %#v, want %#v", got, expected)
	}
}

type FakeValidator struct{}

func (fv *FakeValidator) Validate(i interface{}) error {
	req, ok := i.(*model.RequestLifeCycleCVE)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	if req.ReportCode == "" {
		return fmt.Errorf("report_code is required")
	}
	return nil
}

func TestCVEHandler_LifecycleCVE(t *testing.T) {
	// Setup common test data
	t.Skip()
	mockCVEs := []*model.CVE{
		{ID: "cve-1", Name: "CVE-1234"},
		{ID: "cve-2", Name: "CVE-5678"},
	}

	tests := []struct {
		name            string
		requestBody     string
		setupMocks      func(*mocks.GlobalRepository, *mocks.EnrichmentRepository, *mocks.CVERepository, *mocks.CVELifeCycleV2Repository)
		expectedCode    int
		expectedBody    map[string]interface{}
		customValidator echo.Validator
	}{
		{
			name:        "Invalid JSON",
			requestBody: `{invalid json}`,
			setupMocks: func(mockElastic *mocks.GlobalRepository, mockEnrichment *mocks.EnrichmentRepository, mockCVE *mocks.CVERepository, mockCVELifeCycle *mocks.CVELifeCycleV2Repository) {
				// No mocks needed for invalid JSON case
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"message": "Bad Request",
				"detail":  nil,
			},
		},
		{
			name:        "Validation Error - Missing report_code",
			requestBody: `{}`,
			setupMocks: func(mockElastic *mocks.GlobalRepository, mockEnrichment *mocks.EnrichmentRepository, mockCVE *mocks.CVERepository, mockCVELifeCycle *mocks.CVELifeCycleV2Repository) {
				// No mocks needed for validation error case
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"message": "Bad Request",
				"detail":  nil,
			},
		},
		{
			name:        "Valid request - Success",
			requestBody: `{"report_code":"abc"}`,
			setupMocks: func(mockElastic *mocks.GlobalRepository, mockEnrichment *mocks.EnrichmentRepository, mockCVE *mocks.CVERepository, mockCVELifeCycle *mocks.CVELifeCycleV2Repository) {
				// Setup repository chain
				mockElastic.On("Enrichment").Return(mockEnrichment)
				mockEnrichment.On("CVE").Return(mockCVE)
				mockEnrichment.On("CVELifeCycleV2").Return(mockCVELifeCycle)

				// Setup mock behaviors
				mockCVE.On("Find", mock.Anything, mock.Anything, mock.Anything, 0, 0).
					Return(mockCVEs, nil)
				mockCVELifeCycle.On("FindBulk", mock.Anything, mock.Anything).
					Return([]*model.CVELifeCycleV2{}, nil)
				mockCVELifeCycle.On("StoreBulk", mock.Anything, mock.Anything).
					Return(nil)
			},
			expectedCode: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"message": "OK",
				"detail": map[string]interface{}{
					"message": true,
				},
			},
		},
		{
			name:        "Database Error - CVE Find fails",
			requestBody: `{"report_code":"abc"}`,
			setupMocks: func(mockElastic *mocks.GlobalRepository, mockEnrichment *mocks.EnrichmentRepository, mockCVE *mocks.CVERepository, mockCVELifeCycle *mocks.CVELifeCycleV2Repository) {
				mockElastic.On("Enrichment").Return(mockEnrichment)
				mockEnrichment.On("CVE").Return(mockCVE)

				mockCVE.On("Find", mock.Anything, mock.Anything, mock.Anything, 0, 0).
					Return([]*model.CVE(nil), errors.New("database connection failed"))
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"message": "Bad Request",
				"detail":  nil,
			},
		},
		{
			name:        "Database Error - CVELifeCycle FindBulk fails",
			requestBody: `{"report_code":"abc"}`,
			setupMocks: func(mockElastic *mocks.GlobalRepository, mockEnrichment *mocks.EnrichmentRepository, mockCVE *mocks.CVERepository, mockCVELifeCycle *mocks.CVELifeCycleV2Repository) {
				mockElastic.On("Enrichment").Return(mockEnrichment)
				mockEnrichment.On("CVE").Return(mockCVE)
				mockEnrichment.On("CVELifeCycleV2").Return(mockCVELifeCycle)

				mockCVE.On("Find", mock.Anything, mock.Anything, mock.Anything, 0, 0).
					Return(mockCVEs, nil)
				mockCVELifeCycle.On("FindBulk", mock.Anything, mock.Anything).
					Return([]*model.CVELifeCycleV2(nil), errors.New("query failed"))
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"message": "Bad Request",
				"detail":  nil,
			},
		},
		{
			name:        "Empty CVE result",
			requestBody: `{"report_code":"empty"}`,
			setupMocks: func(mockElastic *mocks.GlobalRepository, mockEnrichment *mocks.EnrichmentRepository, mockCVE *mocks.CVERepository, mockCVELifeCycle *mocks.CVELifeCycleV2Repository) {
				mockElastic.On("Enrichment").Return(mockEnrichment)
				mockEnrichment.On("CVE").Return(mockCVE)
				mockEnrichment.On("CVELifeCycleV2").Return(mockCVELifeCycle)

				mockCVE.On("Find", mock.Anything, mock.Anything, mock.Anything, 0, 0).
					Return([]*model.CVE{}, nil)
				mockCVELifeCycle.On("FindBulk", mock.Anything, mock.Anything).
					Return([]*model.CVELifeCycleV2{}, nil)
				mockCVELifeCycle.On("StoreBulk", mock.Anything, mock.Anything).
					Return(nil)
			},
			expectedCode: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"message": "OK",
				"detail": map[string]interface{}{
					"message": true,
				},
			},
		},
		{
			name:        "StoreBulk fails",
			requestBody: `{"report_code":"store_fail"}`,
			setupMocks: func(mockElastic *mocks.GlobalRepository, mockEnrichment *mocks.EnrichmentRepository, mockCVE *mocks.CVERepository, mockCVELifeCycle *mocks.CVELifeCycleV2Repository) {
				mockElastic.On("Enrichment").Return(mockEnrichment)
				mockEnrichment.On("CVE").Return(mockCVE)
				mockEnrichment.On("CVELifeCycleV2").Return(mockCVELifeCycle)

				mockCVE.On("Find", mock.Anything, mock.Anything, mock.Anything, 0, 0).
					Return(mockCVEs, nil)
				mockCVELifeCycle.On("FindBulk", mock.Anything, mock.Anything).
					Return([]*model.CVELifeCycleV2{}, nil)
				mockCVELifeCycle.On("StoreBulk", mock.Anything, mock.Anything).
					Return(errors.New("storage failed"))
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"message": "Bad Request",
				"detail":  nil,
			},
		},
		{
			name:        "Update existing CVELifecycle with new ReportCode",
			requestBody: `{"report_code":"report-abc","cve_code":["CVE-1234"]}`,
			setupMocks: func(mockElastic *mocks.GlobalRepository, mockEnrichment *mocks.EnrichmentRepository, mockCVE *mocks.CVERepository, mockCVELifeCycle *mocks.CVELifeCycleV2Repository) {
				mockElastic.On("Enrichment").Return(mockEnrichment)
				mockEnrichment.On("CVE").Return(mockCVE)
				mockEnrichment.On("CVELifeCycleV2").Return(mockCVELifeCycle)

				// CVE existed
				mockCVEs := []*model.CVE{
					{ID: "cve-1", Name: "CVE-1234"},
				}
				mockCVE.On("Find", mock.Anything, mock.Anything, mock.Anything, 0, 0).
					Return(mockCVEs, nil)

				// Existing CVELifecycle already has CVECode, but missing ReportCode
				mockCVELifeCycle.On("FindBulk", mock.Anything, mock.Anything).
					Return([]*model.CVELifeCycleV2{
						{
							CVECode:    "CVE-1234",
							References: []string{}, // no report code yet
						},
					}, nil)

				// Expect Update to be called
				mockCVELifeCycle.On("Update", mock.Anything, mock.MatchedBy(func(item *model.CVELifeCycleV2) bool {
					return item.CVECode == "CVE-1234" && slices.Contains(item.References, "report-abc")
				})).Return(nil)

				mockCVELifeCycle.On("StoreBulk", mock.Anything, mock.Anything).
					Return(nil)
			},
			expectedCode: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"message": "OK",
				"detail": map[string]interface{}{
					"message": true,
				},
			},
		},
		{
			name:        "CVELifeCycleV2().Update have error",
			requestBody: `{"report_code":"report-abc","cve_code":["CVE-1234"]}`,
			setupMocks: func(mockElastic *mocks.GlobalRepository, mockEnrichment *mocks.EnrichmentRepository, mockCVE *mocks.CVERepository, mockCVELifeCycle *mocks.CVELifeCycleV2Repository) {
				mockElastic.On("Enrichment").Return(mockEnrichment)
				mockEnrichment.On("CVE").Return(mockCVE)
				mockEnrichment.On("CVELifeCycleV2").Return(mockCVELifeCycle)

				// CVE existed
				mockCVEs := []*model.CVE{
					{ID: "cve-1", Name: "CVE-1234"},
				}
				mockCVE.On("Find", mock.Anything, mock.Anything, mock.Anything, 0, 0).
					Return(mockCVEs, nil)

				// Existing CVELifecycle already has CVECode, but missing ReportCode
				mockCVELifeCycle.On("FindBulk", mock.Anything, mock.Anything).
					Return([]*model.CVELifeCycleV2{
						{
							CVECode:    "CVE-1234",
							References: []string{}, // no report code yet
						},
					}, nil)

				// Expect Update to be called
				mockCVELifeCycle.On("Update", mock.Anything, mock.MatchedBy(func(item *model.CVELifeCycleV2) bool {
					return item.CVECode == "CVE-1234" && slices.Contains(item.References, "report-abc")
				})).Return(fmt.Errorf("Have some error"))

			},
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh mocks for each test case
			mockElastic := new(mocks.GlobalRepository)
			mockEnrichment := new(mocks.EnrichmentRepository)
			mockCVE := new(mocks.CVERepository)
			mockCVELifeCycle := new(mocks.CVELifeCycleV2Repository)

			// Setup mocks using the test-specific function
			tt.setupMocks(mockElastic, mockEnrichment, mockCVE, mockCVELifeCycle)

			// Setup Echo server
			e := echo.New()
			if tt.customValidator != nil {
				e.Validator = tt.customValidator
			} else {
				e.Validator = &FakeValidator{}
			}

			// Create request and response recorder
			req := httptest.NewRequest(http.MethodPost, "/lifecycle-cve", bytes.NewBufferString(tt.requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Create handler and execute
			h := &CVEHandler{
				elastic: mockElastic,
				isTest:  true,
			}

			err := h.LifecycleCVE(c)

			// Assert results
			assert.NoError(t, err, "Handler should not return error")
			assert.Equal(t, tt.expectedCode, rec.Code, "HTTP status code mismatch")

			var got map[string]interface{}
			err = json.Unmarshal(rec.Body.Bytes(), &got)
			assert.NoError(t, err, "Response should be valid JSON")

			// Verify all mocks were called as expected
			mockElastic.AssertExpectations(t)
			mockEnrichment.AssertExpectations(t)
			mockCVE.AssertExpectations(t)
			mockCVELifeCycle.AssertExpectations(t)
		})
	}
}

func TestRequestCVESearch_PrepareQuery(t *testing.T) {
	tests := []struct {
		name     string
		input    *model.RequestCVESearch
		validate func(t *testing.T, query map[string]interface{})
	}{
		{
			name:  "Empty request should return match_all",
			input: &model.RequestCVESearch{},
			validate: func(t *testing.T, query map[string]interface{}) {
				assert.Equal(t, defs.ElasticsearchQueryFilterMatchAll, query)
			},
		},
		{
			name: "With Keyword",
			input: &model.RequestCVESearch{
				Keyword: "openssl",
			},
			validate: func(t *testing.T, query map[string]interface{}) {
				boolQuery := query["bool"].(map[string]interface{})
				filters := boolQuery["filter"].([]interface{})
				assert.NotEmpty(t, filters)
				found := false
				for _, f := range filters {
					b, ok := f.(map[string]interface{})["bool"]
					if !ok {
						continue
					}
					bMap := b.(map[string]interface{})
					if _, hasShould := bMap["should"]; hasShould {
						found = true
						break
					}
				}
				assert.True(t, found, "expected 'should' clause for keyword")
			},
		},
		{
			name: "With Customers",
			input: &model.RequestCVESearch{
				Customers: []string{"customer1", "customer2"},
			},
			validate: func(t *testing.T, query map[string]interface{}) {
				filters := query["bool"].(map[string]interface{})["filter"].([]interface{})
				found := false
				for _, f := range filters {
					if terms, ok := f.(map[string]interface{})["terms"]; ok {
						if customers, exists := terms.(map[string]interface{})["customer"]; exists {
							assert.ElementsMatch(t, []string{"customer1", "customer2"}, customers.([]string))
							found = true
						}
					}
				}
				assert.True(t, found)
			},
		},
		{
			name: "With Checker",
			input: &model.RequestCVESearch{
				Checker: "test-checker",
			},
			validate: func(t *testing.T, query map[string]interface{}) {
				filters := query["bool"].(map[string]interface{})["filter"].([]interface{})
				termFilter := filters[0].(map[string]interface{})["term"].(map[string]interface{})
				assert.Equal(t, "test-checker", termFilter["checker"])
			},
		},
		{
			name: "With Status",
			input: &model.RequestCVESearch{
				Status: []int{1, 2, 3},
			},
			validate: func(t *testing.T, query map[string]interface{}) {
				filters := query["bool"].(map[string]interface{})["filter"].([]interface{})
				found := false
				for _, f := range filters {
					if terms, ok := f.(map[string]interface{})["terms"]; ok {
						if statuses, exists := terms.(map[string]interface{})["status"]; exists {
							assert.ElementsMatch(t, []int{1, 2, 3}, statuses.([]int))
							found = true
						}
					}
				}
				assert.True(t, found)
			},
		},
		{
			name: "With Approved Time",
			input: &model.RequestCVESearch{
				Time: model.CVESearchTime{
					Approved: model.RangeInt64{
						Gte: 1609459200000,
						Lte: 1640995200000,
					},
				},
			},
			validate: func(t *testing.T, query map[string]interface{}) {
				filters := query["bool"].(map[string]interface{})["filter"].([]interface{})
				found := false
				for _, f := range filters {
					if r, ok := f.(map[string]interface{})["range"]; ok {
						if approved, exists := r.(map[string]interface{})["approved"]; exists {
							approvedRange := approved.(map[string]interface{})
							assert.Contains(t, approvedRange, "gte")
							assert.Contains(t, approvedRange, "lte")
							found = true
						}
					}
				}
				assert.True(t, found)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := tt.input.PrepareQuery()
			tt.validate(t, query)
		})
	}
}

func TestRequestCVESearch_PrepareQuery_Severity(t *testing.T) {
	tests := []struct {
		name     string
		input    *model.RequestCVESearch
		validate func(t *testing.T, query map[string]interface{})
	}{
		{
			name: "VTI Severity Version & Value",
			input: &model.RequestCVESearch{
				Severity: model.RequestCVESeverity{
					VTI: model.RequestCVESeverityVerbose{
						Version: "1.0",
						Value:   []int{1, 2, 3, 4},
					},
				},
			},
			validate: func(t *testing.T, query map[string]interface{}) {
				filters := query["bool"].(map[string]interface{})["filter"].([]interface{})
				assert.GreaterOrEqual(t, len(filters), 2)
				versionFilter := filters[0].(map[string]interface{})["term"].(map[string]interface{})
				assert.Equal(t, "1.0", versionFilter["score.vti.version"])

				valueFilter := filters[1].(map[string]interface{})["terms"].(map[string]interface{})
				assert.ElementsMatch(t, []int{1, 2, 3, 4}, valueFilter["score.vti.severity"].([]int))
			},
		},
		{
			name: "Global Severity: CVSSv2",
			input: &model.RequestCVESearch{
				Severity: model.RequestCVESeverity{
					Global: model.RequestCVESeverityVerboseV2{
						Version:          []string{defs.VersionCvssV2},
						SeverityVersion2: []int{1, 2},
					},
				},
			},
			validate: func(t *testing.T, query map[string]interface{}) {
				filters := query["bool"].(map[string]interface{})["filter"].([]interface{})
				assert.NotEmpty(t, filters)
			},
		},
		{
			name: "Global Severity: CVSSv3",
			input: &model.RequestCVESearch{
				Severity: model.RequestCVESeverity{
					Global: model.RequestCVESeverityVerboseV2{
						Version:          []string{defs.VersionCvssV3},
						SeverityVersion3: []int{3},
					},
				},
			},
			validate: func(t *testing.T, query map[string]interface{}) {
				filters := query["bool"].(map[string]interface{})["filter"].([]interface{})
				assert.NotEmpty(t, filters)
			},
		},
		{
			name: "Global Severity: CVSSv34",
			input: &model.RequestCVESearch{
				Severity: model.RequestCVESeverity{
					Global: model.RequestCVESeverityVerboseV2{
						Version:          []string{defs.VersionCvssV4},
						SeverityVersion3: []int{4},
					},
				},
			},
			validate: func(t *testing.T, query map[string]interface{}) {
				filters := query["bool"].(map[string]interface{})["filter"].([]interface{})
				assert.NotEmpty(t, filters)
			},
		},
		{
			name: "Global Severity: CNA",
			input: &model.RequestCVESearch{
				Severity: model.RequestCVESeverity{
					Global: model.RequestCVESeverityVerboseV2{
						Version:            []string{defs.VersionCvssCNA},
						SeverityVersionCNA: []int{1, 2, 3, 4},
					},
				},
			},
			validate: func(t *testing.T, query map[string]interface{}) {
				filters := query["bool"].(map[string]interface{})["filter"].([]interface{})
				assert.NotEmpty(t, filters)
			},
		},
		{
			name: "Global Severity: Unknown version",
			input: &model.RequestCVESearch{
				Severity: model.RequestCVESeverity{
					Global: model.RequestCVESeverityVerboseV2{
						Version: []string{"unknown-version"},
					},
				},
			},
			validate: func(t *testing.T, query map[string]interface{}) {
				filters := query["bool"].(map[string]interface{})["filter"].([]interface{})
				// expect term with empty version
				found := false
				for _, f := range filters {
					b, ok := f.(map[string]interface{})["bool"]
					if !ok {
						continue
					}
					should, ok := b.(map[string]interface{})["should"]
					if !ok {
						continue
					}
					for _, clause := range should.([]interface{}) {
						if term, ok := clause.(map[string]interface{})["term"]; ok {
							if val, ok := term.(map[string]interface{})["score.global.version"]; ok {
								if val == "" {
									found = true
								}
							}
						}
					}
				}
				assert.True(t, found)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := tt.input.PrepareQuery()
			tt.validate(t, query)
		})
	}
}

func TestRequestCVESearch_PrepareQuery_Languages(t *testing.T) {
	tests := []struct {
		name                string
		input               *model.RequestCVESearch
		expectedFilterCount int
	}{
		{
			name: "Languages: Single (en)",
			input: &model.RequestCVESearch{
				Languages: []string{"en"},
			},
			expectedFilterCount: 2, // should + must_not
		},
		{
			name: "Languages: Multiple (en, vi)",
			input: &model.RequestCVESearch{
				Languages: []string{"en", "vi"},
			},
			expectedFilterCount: 1,
		},
		{
			name: "Languages: Combined vi,en",
			input: &model.RequestCVESearch{
				Languages: []string{"vi,en"},
			},
			expectedFilterCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.PrepareQuery()
			boolQuery := result["bool"].(map[string]interface{})
			filters := boolQuery["filter"].([]interface{})
			assert.Len(t, filters, tt.expectedFilterCount)
		})
	}
}

type CustomValidatora struct {
	validator *validator.Validate
}

func (cv *CustomValidatora) Validate(i interface{}) error {
	return cv.validator.Struct(i)
}

func TestValidateCVE(t *testing.T) {
	t.Skip()
	tests := []struct {
		name           string
		requestBody    string
		setupMocks     func(cveRepo *mocks.CVERepository, enrichment *mocks.EnrichmentRepository, elastic *mocks.GlobalRepository)
		expectedStatus int
	}{
		{
			name:           "Invalid JSON",
			requestBody:    `{invalid json`,
			setupMocks:     nil, // không cần mock elastic
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid size < 0",
			requestBody:    `{"size": -1, "offset": 0}`,
			setupMocks:     nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Elastic returns unexpected error",
			requestBody: `{"size": 10, "offset": 0}`,
			setupMocks: func(cveRepo *mocks.CVERepository, enrichment *mocks.EnrichmentRepository, elastic *mocks.GlobalRepository) {
				cveRepo.On("Find", mock.Anything, mock.Anything, mock.Anything, 0, 10).
					Return(nil, errors.New("db error")).Once()
				enrichment.On("CVE").Return(cveRepo).Once()
				elastic.On("Enrichment").Return(enrichment).Once()
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "ok",
			requestBody: `{"size": 10, "offset": 0}`,
			setupMocks: func(cveRepo *mocks.CVERepository, enrichment *mocks.EnrichmentRepository, elastic *mocks.GlobalRepository) {
				cveRepo.On("Find", mock.Anything, mock.Anything, mock.Anything, 0, 10).
					Return(nil, nil).Once()
				enrichment.On("CVE").Return(cveRepo).Once()
				elastic.On("Enrichment").Return(enrichment).Once()
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "len(results) > 0",
			requestBody: `{"size": 10, "offset": 0}`,
			setupMocks: func(cveRepo *mocks.CVERepository, enrichment *mocks.EnrichmentRepository, elastic *mocks.GlobalRepository) {
				cveRepo.On("Find", mock.Anything, mock.Anything, mock.Anything, 0, 10).
					Return([]*model.CVE{{ID: "happy case"}}, nil).Once()
				enrichment.On("CVE").Return(cveRepo).Once()
				elastic.On("Enrichment").Return(enrichment).Once()
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			e.Validator = &CustomValidatora{validator: validator.New()}

			req := httptest.NewRequest(http.MethodPost, "/validate-cve", strings.NewReader(tt.requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Setup mocks if needed
			mockElastic := mocks.NewGlobalRepository(t)
			mockEnrichment := mocks.NewEnrichmentRepository(t)
			mockCVERepo := mocks.NewCVERepository(t)

			if tt.setupMocks != nil {
				tt.setupMocks(mockCVERepo, mockEnrichment, mockElastic)
			}

			h := &CVEHandler{
				elastic: mockElastic,
			}

			err := h.ValidateCVE(c)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			var got map[string]interface{}
			_ = json.Unmarshal(rec.Body.Bytes(), &got)

		})
	}
}

func TestCVEHandler_Detail_ThreatReports(t *testing.T) {
	tests := []struct {
		name           string
		paramID        string
		setupMocks     func(mongo *mockmg.GlobalRepository, threat *mockmg.ThreatReportRepository)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/:id", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Set route param ":id"
			c.SetParamNames("id")
			c.SetParamValues(tt.paramID)

			// Mocks
			mockMongo := mockmg.NewGlobalRepository(t)
			mockThreat := mockmg.NewThreatReportRepository(t)
			if tt.setupMocks != nil {
				tt.setupMocks(mockMongo, mockThreat)
			}

			// Handler
			h := &CVEHandler{mongo: mockMongo} // Ensure handler has threat repo
			err := h.Detail(c)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			var got map[string]interface{}
			_ = json.Unmarshal(rec.Body.Bytes(), &got)

			// Compare only ThreatReports for simplicity
			if tt.expectedBody["ThreatReports"] != nil {
				assert.Equal(t, tt.expectedBody["ThreatReports"], got["ThreatReports"])
			} else {
				assert.Equal(t, tt.expectedBody, got)
			}
		})
	}
}

func TestValidateCVSSVectorString(t *testing.T) {
	tests := []struct {
		name         string
		version      string
		vectorString string
		expected     bool
	}{
		{
			name:         "Valid CVSS v2.0",
			version:      "2.0",
			vectorString: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			expected:     true,
		},
		{
			name:         "Valid CVSS v3.1",
			version:      "3.1",
			vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expected:     true,
		},
		{
			name:         "Valid CVSS v4.0",
			version:      "4.0",
			vectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
			expected:     true,
		},
		{
			name:         "Invalid version",
			version:      "5.0",
			vectorString: "whatever",
			expected:     false,
		},
		{
			name:         "Invalid vector for v2.0",
			version:      "2.0",
			vectorString: "AV:X/AC:L/Au:N/C:P/I:P/A:P",
			expected:     false,
		},
		{
			name:         "Invalid vector for v3.1 - missing prefix",
			version:      "3.1",
			vectorString: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expected:     false,
		},
		{
			name:         "Empty vector string",
			version:      "3.1",
			vectorString: "",
			expected:     false,
		},
		{
			name:         "Empty version",
			version:      "",
			vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCVSSVectorString(tt.version, tt.vectorString)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_validateLanguage(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:        "Valid language en",
			input:       "en",
			expected:    "en",
			expectError: false,
		},
		{
			name:        "Valid language vi",
			input:       "vi",
			expected:    "vi",
			expectError: false,
		},
		{
			name:        "Language with spaces",
			input:       " vi ",
			expected:    "vi",
			expectError: false,
		},
		{
			name:        "Empty language",
			input:       "   ",
			expectError: true,
		},
		{
			name:        "Invalid language",
			input:       "jp",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateLanguage(tt.input)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func Test_validateCVEID(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:        "Valid CVE ID lowercase",
			input:       "cve-2023-12345",
			expected:    "CVE-2023-12345",
			expectError: false,
		},
		{
			name:        "Valid CVE ID uppercase",
			input:       "CVE-2021-0001",
			expected:    "CVE-2021-0001",
			expectError: false,
		},
		{
			name:        "Invalid CVE ID format (no dash)",
			input:       "CVE2023-1234",
			expectError: true,
		},
		{
			name:        "Invalid CVE ID format (missing part)",
			input:       "CVE-2023",
			expectError: true,
		},
		{
			name:        "Invalid CVE ID format (non-numeric)",
			input:       "CVE-20AB-XYZZ",
			expectError: true,
		},
		{
			name:        "Valid CVE ID with long digits",
			input:       "cve-1999-123456",
			expected:    "CVE-1999-123456",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateCVEID(tt.input)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func Test_validateCWE(t *testing.T) {
	t.Skip()
	tests := []struct {
		name        string
		input       []model.CWEMetric
		expected    []model.CWEMetric
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Empty CWE array",
			input:       []model.CWEMetric{},
			expected:    []model.CWEMetric{},
			expectError: false,
		},
		{
			name: "Valid single CWE",
			input: []model.CWEMetric{
				{ID: " CWE-79 ", Name: "Cross-site Scripting", Link: " https://cwe.mitre.org/data/definitions/79.html "},
			},
			expected: []model.CWEMetric{
				{ID: "CWE-79", Name: "Cross-site Scripting", Link: "https://cwe.mitre.org/data/definitions/79.html"},
			},
			expectError: false,
		},
		{
			name: "Missing CWE ID",
			input: []model.CWEMetric{
				{ID: " ", Name: "SQL Injection", Link: "https://link"},
			},
			expectError: true,
			errorMsg:    "CWE ID is required for item 1",
		},
		{
			name: "Invalid CWE ID format",
			input: []model.CWEMetric{
				{ID: "CWE79", Name: "XSS", Link: "https://link"},
			},
			expectError: true,
			errorMsg:    "invalid CWE ID format for item 1: must be CWE-XXXX",
		},
		{
			name: "Missing Name",
			input: []model.CWEMetric{
				{ID: "CWE-89", Name: "", Link: "https://link"},
			},
			expectError: true,
			errorMsg:    "CWE Name is required for item 1",
		},
		{
			name: "Missing Link",
			input: []model.CWEMetric{
				{ID: "CWE-89", Name: "SQL Injection", Link: ""},
			},
			expectError: true,
			errorMsg:    "link is required for item 1",
		},
		{
			name: "Duplicate CWE ID",
			input: []model.CWEMetric{
				{ID: "CWE-89", Name: "SQL Injection", Link: "https://link"},
				{ID: "CWE-89", Name: "Also SQL Injection", Link: "https://link2"},
			},
			expectError: true,
			errorMsg:    "duplicate CWE ID: CWE-89 at item 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateCWE(tt.input)

			if tt.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestValidateEPSS(t *testing.T) {
	tests := []struct {
		name        string
		epss        *model.EPSSMetric
		expectedErr error
	}{
		{
			name: "Valid score and percentile",
			epss: &model.EPSSMetric{
				Score:      float64Ptr(0.75),
				Percentile: float64Ptr(0.85),
			},
			expectedErr: nil,
		},
		{
			name: "Score below range",
			epss: &model.EPSSMetric{
				Score:      float64Ptr(-0.1),
				Percentile: nil,
			},
			expectedErr: fmt.Errorf("invalid score: must be between 0.0 and 1.0"),
		},
		{
			name: "Score above range",
			epss: &model.EPSSMetric{
				Score:      float64Ptr(1.1),
				Percentile: nil,
			},
			expectedErr: fmt.Errorf("invalid score: must be between 0.0 and 1.0"),
		},
		{
			name: "Percentile below range",
			epss: &model.EPSSMetric{
				Score:      nil,
				Percentile: float64Ptr(-0.1),
			},
			expectedErr: fmt.Errorf("invalid percentile: must be between 0.0 and 1.0"),
		},
		{
			name: "Percentile above range",
			epss: &model.EPSSMetric{
				Score:      nil,
				Percentile: float64Ptr(1.1),
			},
			expectedErr: fmt.Errorf("invalid percentile: must be between 0.0 and 1.0"),
		},
		{
			name: "Nil values",
			epss: &model.EPSSMetric{
				Score:      nil,
				Percentile: nil,
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEPSS(tt.epss)
			if tt.expectedErr != nil {
				assert.EqualError(t, err, tt.expectedErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func float64Ptr(f float64) *float64 {
	return &f
}

func Test_validateCVEMetric(t *testing.T) {
	t.Skip()
	tests := []struct {
		name            string
		input           model.CVEMetric
		versionPrefix   string
		versionStandard string
		fieldName       string
		expectedErr     string
		expectedScore   float32
	}{
		{
			name: "Valid input with correct version and vector",
			input: model.CVEMetric{
				Version:      "3.1",
				VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Score:        9.8,
			},
			versionPrefix:   "3",
			versionStandard: "3.1",
			fieldName:       "cvss_v3",
			expectedErr:     "",
			expectedScore:   9.8,
		},
		{
			name: "Missing vector",
			input: model.CVEMetric{
				Version: "3.1",
			},
			versionPrefix:   "3",
			versionStandard: "3.1",
			fieldName:       "cvss_v3",
			expectedErr:     "cvss_v3: must provide all fields: version, vectorString",
		},
		{
			name: "Invalid version prefix",
			input: model.CVEMetric{
				Version:      "2.1",
				VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
			versionPrefix:   "3",
			versionStandard: "3.1",
			fieldName:       "cvss_v3",
			expectedErr:     "cvss_v3.version must be version 3.x",
		},
		{
			name: "Invalid vector format",
			input: model.CVEMetric{
				Version:      "3.1",
				VectorString: "invalid:vector",
			},
			versionPrefix:   "3",
			versionStandard: "3.1",
			fieldName:       "cvss_v3",
			expectedErr:     "cvss_v3.vectorString does not match version 3 format",
		},
		{
			name: "Score out of range (too high)",
			input: model.CVEMetric{
				Version:      "3.1",
				VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Score:        11.0,
			},
			versionPrefix:   "3",
			versionStandard: "3.1",
			fieldName:       "cvss_v3",
			expectedErr:     "invalid value for cvss_v3.score",
		},
		{
			name: "Score should be rounded",
			input: model.CVEMetric{
				Version:      "3.1",
				VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Score:        5.234,
			},
			versionPrefix:   "3",
			versionStandard: "3.1",
			fieldName:       "cvss_v3",
			expectedErr:     "",
			expectedScore:   5.2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateCVEMetric(tt.input, tt.versionStandard, tt.fieldName)
			if tt.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
				if tt.input.Score != 0 {
					require.Equal(t, tt.expectedScore, got.Score)
				}
				require.Equal(t, tt.versionStandard, got.Version)
			}
		})
	}
}

var mockValidateCVEMetric func(metric model.CVEMetric, version, expectedVersion, fieldName string) (model.CVEMetric, error)

// Override validateCVEMetric trong test
func init() {
	// Backup original function nếu cần
	originalValidateCVEMetric := validateCVEMetric
	_ = originalValidateCVEMetric
}

func TestValidateCVSS(t *testing.T) {
	t.Skip()
	tests := []struct {
		name           string
		input          model.CVSSMetric
		mockSetup      func()
		expectedResult model.CVSSMetric
		expectedError  string
	}{
		{
			name: "Valid CVSS metrics - all versions",
			input: model.CVSSMetric{
				CVSS2: model.CVEMetric{
					Score:        7.5,
					Version:      "2.0",
					Severity:     3,
					VectorString: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				},
				CVSS3: model.CVEMetric{
					Score:        8.8,
					Version:      "3.1",
					Severity:     3,
					VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
				},
				CVSS4: model.CVEMetric{
					Score:        9.0,
					Version:      "4.0",
					Severity:     4,
					VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				},
			},
			mockSetup: func() {
				mockValidateCVEMetric = func(metric model.CVEMetric, version, expectedVersion, fieldName string) (model.CVEMetric, error) {
					return metric, nil
				}
			},
			expectedResult: model.CVSSMetric{
				CVSS2: model.CVEMetric{
					Score:        7.5,
					Version:      "2.0",
					Severity:     3,
					VectorString: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				},
				CVSS3: model.CVEMetric{
					Score:        8.8,
					Version:      "3.1",
					Severity:     3,
					VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
				},
				CVSS4: model.CVEMetric{
					Score:        9.0,
					Version:      "4.0",
					Severity:     4,
					VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				},
			},
			expectedError: "",
		},

		{
			name: "Empty CVSS metrics - should pass validation",
			input: model.CVSSMetric{
				CVSS2: model.CVEMetric{},
				CVSS3: model.CVEMetric{},
				CVSS4: model.CVEMetric{},
			},
			mockSetup: func() {
				mockValidateCVEMetric = func(metric model.CVEMetric, version, expectedVersion, fieldName string) (model.CVEMetric, error) {
					return metric, nil
				}
			},
			expectedResult: model.CVSSMetric{
				CVSS2: model.CVEMetric{},
				CVSS3: model.CVEMetric{},
				CVSS4: model.CVEMetric{},
			},
			expectedError: "",
		},
		{
			name: "Only CVSS3 provided",
			input: model.CVSSMetric{
				CVSS2: model.CVEMetric{},
				CVSS3: model.CVEMetric{
					Score:        6.1,
					Version:      "3.1",
					Severity:     2,
					VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
				},
				CVSS4: model.CVEMetric{},
			},
			mockSetup: func() {
				mockValidateCVEMetric = func(metric model.CVEMetric, version, expectedVersion, fieldName string) (model.CVEMetric, error) {
					return metric, nil
				}
			},
			expectedResult: model.CVSSMetric{
				CVSS2: model.CVEMetric{},
				CVSS3: model.CVEMetric{
					Score:        6.1,
					Version:      "3.1",
					Severity:     2,
					VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
				},
				CVSS4: model.CVEMetric{},
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock
			tt.mockSetup()

			// Execute test
			result, err := validateCVSS(tt.input)

			// Assertions
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Equal(t, model.CVSSMetric{}, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

func TestCVEHandler_verifyCVELifeCycleV2(t *testing.T) {
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}

	tests := []struct {
		name             string
		requestBody      string
		overrideValidate func(c echo.Context, body interface{}) error
		expectError      bool
		expectIDHash     bool
		expectSize       int
	}{
		{
			name:        "Invalid JSON causes Validate error",
			requestBody: `{invalid}`,
			overrideValidate: func(c echo.Context, body interface{}) error {
				return fmt.Errorf("validate error")
			},
			expectError: true,
		},
		{
			name:         "ID contains cve- triggers SHA1",
			requestBody:  `{"id":"cve-1234","from_date":0,"to_date":0,"size":0}`,
			expectError:  false,
			expectIDHash: true,
			expectSize:   10,
		},
		{
			name:         "invalidDateRange  true",
			requestBody:  `{"id":"cve-1234","from_data":15,"to_data":10,"size":0}`,
			expectError:  true,
			expectIDHash: true,
			expectSize:   10,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := &CVEHandler{}
			body, err := handler.verifyCVELifeCycleV2(c)

			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tc.expectIDHash {
				assert.Equal(t, 40, len(body.ID))
			}
			if tc.expectSize > 0 {
				assert.Equal(t, tc.expectSize, body.Size)
			}
		})
	}
}

func TestCVEHandler_verifyHistoryEPSS(t *testing.T) {
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}

	tests := []struct {
		name        string
		requestBody string
		expectError bool
		expectID    string
		expectSize  int
	}{
		{
			name:        "Invalid JSON triggers Validate error",
			requestBody: `{invalid}`,
			expectError: true,
		},
		{
			name:        "ID missing CVE- prefix returns error",
			requestBody: `{"id":"1234","from_date":0,"to_date":0,"size":1}`,
			expectError: true,
		},
		{
			name:        "ID with CVE- and size=0 sets default size",
			requestBody: `{"id":"cve-1234","from_date":0,"to_date":0,"size":0}`,
			expectError: false,
			expectID:    "CVE-1234",
			expectSize:  10,
		},
		{
			name:        "ID with spaces is trimmed and uppercased",
			requestBody: `{"id":"  cve-123 ","from_date":0,"to_date":0,"size":1}`,
			expectError: false,
			expectID:    "CVE-123",
			expectSize:  1,
		},
		{
			name:        "Valid date range sets default size",
			requestBody: `{"id":"cve-1","from_date":1,"to_date":2,"size":0}`,
			expectError: false,
			expectID:    "CVE-1",
			expectSize:  10,
		},
		{
			name:        "invalidDateRange",
			requestBody: `{"id":"cve-1","from_data":15,"to_data":10,"size":0}`,
			expectError: true,
			expectID:    "CVE-1",
			expectSize:  10,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := &CVEHandler{}
			body, err := handler.verifyHistoryEPSS(c)

			if tc.expectError {
				require.Error(t, err)
				if strings.Contains(tc.name, "date range") {
					assert.Contains(t, err.Error(), "must be provided together")
				}
				if strings.Contains(tc.name, "prefix") {
					assert.Contains(t, err.Error(), "CVE-")
				}
				return
			}

			require.NoError(t, err)
			if tc.expectID != "" {
				assert.Equal(t, tc.expectID, body.ID)
			}
			if tc.expectSize > 0 {
				assert.Equal(t, tc.expectSize, body.Size)
			}
		})
	}
}

func TestCVEHandler_verifyHistory(t *testing.T) {
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}

	tests := []struct {
		name         string
		requestBody  string
		expectError  bool
		expectIDHash bool
		expectSize   int
	}{
		{
			name:        "Invalid JSON triggers Validate error",
			requestBody: `{invalid}`,
			expectError: true,
		},
		{
			name:         "ID contains cve- triggers SHA1 + default size",
			requestBody:  `{"id":"cve-1234","from_date":0,"to_date":0,"size":0}`,
			expectError:  false,
			expectIDHash: true,
			expectSize:   10,
		},
		{
			name:         "ID without cve- only toLower, keep size",
			requestBody:  `{"id":"ABC","from_date":0,"to_date":0,"size":5}`,
			expectError:  false,
			expectIDHash: false,
			expectSize:   5,
		},
		{
			name:        "Valid date range no hash + default size",
			requestBody: `{"id":"abc","from_date":1,"to_date":2,"size":0}`,
			expectError: false,
			expectSize:  10,
		},
		{
			name:        "invalidDateRangeHistory true",
			requestBody: `{"id":"abc","from_data":2,"to_data":1,"size":0}`,
			expectError: true,
			expectSize:  10,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := &CVEHandler{}
			body, err := handler.verifyHistory(c)

			if tc.expectError {
				require.Error(t, err)
				if strings.Contains(tc.name, "date range") {
					assert.Contains(t, err.Error(), "must be provided together")
				}
				return
			}

			require.NoError(t, err)
			if tc.expectIDHash {
				assert.Equal(t, 40, len(body.ID)) // SHA1 length
			} else if body.ID != "" {
				assert.Equal(t, strings.ToLower(body.ID), body.ID) // only toLower
			}
			if tc.expectSize > 0 {
				assert.Equal(t, tc.expectSize, body.Size)
			}
		})
	}
}

type MockChain struct {
	Elastic    *mocks.GlobalRepository
	Enrichment *mocks.EnrichmentRepository
	CVERepo    *mocks.CVELifeCycleV2Repository
}

func NewMockChain() *MockChain {
	mc := &MockChain{
		Elastic:    new(mocks.GlobalRepository),
		Enrichment: new(mocks.EnrichmentRepository),
		CVERepo:    new(mocks.CVELifeCycleV2Repository),
	}
	mc.Elastic.On("Enrichment").Return(mc.Enrichment)
	mc.Enrichment.On("CVELifeCycleV2").Return(mc.CVERepo)
	return mc
}

type MockCVEHandler struct {
	*CVEHandler
	mockVerifyFunc func(echo.Context) (model.RequestCVELifeCycleV2Search, error)
}

func (m *MockCVEHandler) verifyCVELifeCycleV2(c echo.Context) (model.RequestCVELifeCycleV2Search, error) {
	if m.mockVerifyFunc != nil {
		return m.mockVerifyFunc(c)
	}
	return m.CVEHandler.verifyCVELifeCycleV2(c)
}

type CVELifeCycleV2Suite struct {
	suite.Suite
	e       *echo.Echo
	mocks   *MockChain
	handler *MockCVEHandler
}

func (s *CVELifeCycleV2Suite) SetupSuite() {
	s.e = echo.New()
	s.e.Validator = &CustomValidator{validator: validator.New()}
}

func (s *CVELifeCycleV2Suite) SetupTest() {
	s.mocks = NewMockChain()
	realHandler := &CVEHandler{elastic: s.mocks.Elastic}
	s.handler = &MockCVEHandler{CVEHandler: realHandler}
}

//func (s *CVELifeCycleV2Suite) TearDownTest() {
//	s.mocks.CVERepo.AssertExpectations(s.T())
//	s.mocks.Enrichment.AssertExpectations(s.T())
//	s.mocks.Elastic.AssertExpectations(s.T())
//}

func createTestContext(e *echo.Echo, method, path string, body []byte) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues("CVE-2024-7777")
	return ctx, rec
}

//func (s *CVELifeCycleV2Suite) Test_Success() {
//	s.T().Skip()
//	expectedData := []*model.CVELifeCycleV2{
//		{ID: "1", CVEId: "CVE-2024-7777", Event: model.CVE_EVENT_DETECTION},
//	}
//	expectedTotal := int64(1)
//
//	s.handler.mockVerifyFunc = func(c echo.Context) (model.RequestCVELifeCycleV2Search, error) {
//		return model.RequestCVELifeCycleV2Search{Size: 10, Offset: 0}, nil
//	}
//	s.mocks.CVERepo.
//		On("Find", mock.Anything, mock.Anything, []string{"-created"}, 0, 10).
//		Return(expectedData, expectedTotal, nil)
//
//	ctx, rec := createTestContext(s.e, http.MethodGet, "/CVE-2024-7777/lifecycle", nil)
//	err := s.handler.CVELifeCycleV2(ctx)
//
//	s.NoError(err)
//	s.Equal(http.StatusOK, rec.Code)
//
//	var resp model.CVELifecycleV2Response
//	s.NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
//	s.Equal(expectedTotal, resp.Total)
//	s.Len(resp.Data, 1)
//}

//func (s *CVELifeCycleV2Suite) Test_NotFound() {
//	s.T().Skip()
//	s.handler.mockVerifyFunc = func(c echo.Context) (model.RequestCVELifeCycleV2Search, error) {
//		return model.RequestCVELifeCycleV2Search{Size: 10, Offset: 0}, nil
//	}
//
//	s.mocks.CVERepo.
//		On("Find", mock.Anything, mock.Anything, []string{"-created"}, 0, 10).
//		Return(nil, int64(0), errors.New(es.NotFoundError))
//
//	ctx, rec := createTestContext(s.e, http.MethodGet, "/CVE-2024-7777/lifecycle", nil)
//	err := s.handler.CVELifeCycleV2(ctx)
//
//	s.NoError(err)
//	s.Equal(http.StatusOK, rec.Code)
//
//	var resp map[string]interface{}
//	s.NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
//	s.Equal(float64(0), resp["total"])
//	s.IsType([]interface{}{}, resp["data"])
//}

func (s *CVELifeCycleV2Suite) Test_InternalError() {
	s.T().Skip()
	s.handler.mockVerifyFunc = func(c echo.Context) (model.RequestCVELifeCycleV2Search, error) {
		return model.RequestCVELifeCycleV2Search{Size: 10, Offset: 0}, nil
	}

	s.mocks.CVERepo.
		On("Find", mock.Anything, mock.Anything, []string{"-created"}, 0, 10).
		Return(nil, int64(0), errors.New("unexpected ES error"))

	ctx, rec := createTestContext(s.e, http.MethodGet, "/CVE-2024-7777/lifecycle", nil)
	err := s.handler.CVELifeCycleV2(ctx)

	s.NoError(err)
	s.Equal(http.StatusInternalServerError, rec.Code)
}

// =========================
// Run Suite
// =========================

func TestCVELifeCycleV2Suite(t *testing.T) {
	suite.Run(t, new(CVELifeCycleV2Suite))
}

type MockEPSSChain struct {
	Elastic    *mocks.GlobalRepository
	Enrichment *mocks.EnrichmentRepository
	EPSSRepo   *mocks.CVEEPSSHistoryRepository
}

func NewMockEPSSChain() *MockEPSSChain {
	mc := &MockEPSSChain{
		Elastic:    new(mocks.GlobalRepository),
		Enrichment: new(mocks.EnrichmentRepository),
		EPSSRepo:   new(mocks.CVEEPSSHistoryRepository),
	}
	mc.Elastic.On("Enrichment").Return(mc.Enrichment)
	mc.Enrichment.On("CVEEPSSHistory").Return(mc.EPSSRepo)
	return mc
}

type MockEPSSHandler struct {
	*CVEHandler
	mockVerifyFunc func(echo.Context) (model.RequestEPSSHistorySearch, error)
}

func (m *MockEPSSHandler) verifyHistoryEPSS(c echo.Context) (model.RequestEPSSHistorySearch, error) {
	if m.mockVerifyFunc != nil {
		return m.mockVerifyFunc(c)
	}
	return m.CVEHandler.verifyHistoryEPSS(c)
}

type EPSSHistorySuite struct {
	suite.Suite
	e       *echo.Echo
	mocks   *MockEPSSChain
	handler *MockEPSSHandler
}

func (s *EPSSHistorySuite) SetupSuite() {
	s.e = echo.New()
	s.e.Validator = &CustomValidator{validator: validator.New()}
}

func (s *EPSSHistorySuite) SetupTest() {
	s.mocks = NewMockEPSSChain()
	realHandler := &CVEHandler{elastic: s.mocks.Elastic}
	s.handler = &MockEPSSHandler{CVEHandler: realHandler}
}

//func (s *EPSSHistorySuite) TearDownTest() {
//	s.mocks.EPSSRepo.AssertExpectations(s.T())
//	s.mocks.Enrichment.AssertExpectations(s.T())
//	s.mocks.Elastic.AssertExpectations(s.T())
//}

func createEPSSContext(e *echo.Echo, method, path string, body []byte) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues("CVE-2024-7777")
	return ctx, rec
}

// =========================
// Tests
// =========================

//func (s *EPSSHistorySuite) Test_Success() {
//	s.T().Skip()
//	expectedData := []*model.CVEEPSSHistory{
//		{ID: "1", CVEName: "CVE-2024-7777", Date: 1735584000},
//	}
//	expectedTotal := int64(1)
//
//	s.handler.mockVerifyFunc = func(c echo.Context) (model.RequestEPSSHistorySearch, error) {
//		return model.RequestEPSSHistorySearch{Size: 10, Offset: 0}, nil
//	}
//	s.mocks.EPSSRepo.
//		On("Find", mock.Anything, mock.Anything, []string{"-date"}, 0, 10).
//		Return(expectedData, expectedTotal, nil)
//
//	ctx, rec := createEPSSContext(s.e, http.MethodGet, "/CVE-2024-7777/epss-history", nil)
//	err := s.handler.EPSSHistory(ctx)
//
//	s.NoError(err)
//	s.Equal(http.StatusOK, rec.Code)
//
//	var resp model.HistoryEPSSResponse
//	s.NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
//	s.Equal(expectedTotal, resp.Total)
//	s.Len(resp.Data, 1)
//}
//
//func (s *EPSSHistorySuite) Test_NotFound() {
//	s.T().Skip()
//	s.handler.mockVerifyFunc = func(c echo.Context) (model.RequestEPSSHistorySearch, error) {
//		return model.RequestEPSSHistorySearch{Size: 10, Offset: 0}, nil
//	}
//
//	s.mocks.EPSSRepo.
//		On("Find", mock.Anything, mock.Anything, []string{"-date"}, 0, 10).
//		Return(nil, int64(0), errors.New(es.NotFoundError))
//
//	ctx, rec := createEPSSContext(s.e, http.MethodGet, "/CVE-2024-7777/epss-history", nil)
//	err := s.handler.EPSSHistory(ctx)
//
//	s.NoError(err)
//	s.Equal(http.StatusOK, rec.Code)
//
//	var resp map[string]interface{}
//	s.NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
//	s.Equal(float64(0), resp["total"])
//	s.IsType([]interface{}{}, resp["data"])
//}
//
//func (s *EPSSHistorySuite) Test_InternalError() {
//	s.T().Skip()
//	s.handler.mockVerifyFunc = func(c echo.Context) (model.RequestEPSSHistorySearch, error) {
//		return model.RequestEPSSHistorySearch{Size: 10, Offset: 0}, nil
//	}
//
//	s.mocks.EPSSRepo.
//		On("Find", mock.Anything, mock.Anything, []string{"-date"}, 0, 10).
//		Return(nil, int64(0), errors.New("unexpected ES error"))
//
//	ctx, rec := createEPSSContext(s.e, http.MethodGet, "/CVE-2024-7777/epss-history", nil)
//	err := s.handler.EPSSHistory(ctx)
//
//	s.NoError(err)
//	s.Equal(http.StatusInternalServerError, rec.Code)
//}

// =========================
// Run Suite
// =========================

func TestEPSSHistorySuite(t *testing.T) {
	suite.Run(t, new(EPSSHistorySuite))
}

type MockHistoryChain struct {
	Elastic     *mocks.GlobalRepository
	Enrichment  *mocks.EnrichmentRepository
	HistoryRepo *mocks.HistoryRepository
}

func NewMockHistoryChain() *MockHistoryChain {
	mc := &MockHistoryChain{
		Elastic:     new(mocks.GlobalRepository),
		Enrichment:  new(mocks.EnrichmentRepository),
		HistoryRepo: new(mocks.HistoryRepository),
	}
	mc.Elastic.On("Enrichment").Return(mc.Enrichment)
	mc.Enrichment.On("CVEHistory").Return(mc.HistoryRepo)
	return mc
}

type MockCVEHistoryHandler struct {
	*CVEHandler
	mockVerifyFunc func(echo.Context) (model.RequestHistorySearch, error)
}

func (m *MockCVEHistoryHandler) verifyHistory(c echo.Context) (model.RequestHistorySearch, error) {
	if m.mockVerifyFunc != nil {
		return m.mockVerifyFunc(c)
	}
	return m.CVEHandler.verifyHistory(c)
}

// =========================
// Suite
// =========================

type CVEHistorySuite struct {
	suite.Suite
	e       *echo.Echo
	mocks   *MockHistoryChain
	handler *MockCVEHistoryHandler
}

func (s *CVEHistorySuite) SetupSuite() {
	s.e = echo.New()
	s.e.Validator = &CustomValidator{validator: validator.New()}
}

func (s *CVEHistorySuite) SetupTest() {
	s.mocks = NewMockHistoryChain()
	realHandler := &CVEHandler{elastic: s.mocks.Elastic}
	s.handler = &MockCVEHistoryHandler{CVEHandler: realHandler}
}

func (s *CVEHistorySuite) TearDownTest() {
	s.mocks.HistoryRepo.AssertExpectations(s.T())
	s.mocks.Enrichment.AssertExpectations(s.T())
	s.mocks.Elastic.AssertExpectations(s.T())
}

func createHistoryContext(e *echo.Echo, method, path string, body []byte) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues("CVE-2024-7777")
	return ctx, rec
}

// =========================
// Test cases
// =========================

//func (s *CVEHistorySuite) Test_Success() {
//	s.T().Skip()
//	expectedData := []*model.History{
//		{ID: "1", Document: "doc", Editor: "admin", Action: "create"},
//	}
//	expectedTotal := int64(1)
//
//	s.handler.mockVerifyFunc = func(c echo.Context) (model.RequestHistorySearch, error) {
//		return model.RequestHistorySearch{Size: 10, Offset: 0}, nil
//	}
//
//	s.mocks.HistoryRepo.
//		On("Find", mock.Anything, mock.Anything, []string{"-created"}, 0, 10).
//		Return(expectedData, expectedTotal, nil)
//
//	ctx, rec := createHistoryContext(s.e, http.MethodGet, "/CVE-2024-7777/history", nil)
//	err := s.handler.CVEHistory(ctx)
//
//	s.NoError(err)
//	s.Equal(http.StatusOK, rec.Code)
//
//	var resp model.HistoryResponse
//	s.NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
//	s.Equal(expectedTotal, resp.Total)
//	s.Len(resp.Data, 1)
//	s.Equal("doc", resp.Data[0].Document)
//}

//func (s *CVEHistorySuite) Test_NotFound() {
//	s.T().Skip()
//	s.handler.mockVerifyFunc = func(c echo.Context) (model.RequestHistorySearch, error) {
//		return model.RequestHistorySearch{Size: 10, Offset: 0}, nil
//	}
//
//	s.mocks.HistoryRepo.
//		On("Find", mock.Anything, mock.Anything, []string{"-created"}, 0, 10).
//		Return(nil, int64(0), errors.New(es.NotFoundError))
//
//	ctx, rec := createHistoryContext(s.e, http.MethodGet, "/CVE-2024-7777/history", nil)
//	err := s.handler.CVEHistory(ctx)
//
//	s.NoError(err)
//	s.Equal(http.StatusOK, rec.Code)
//
//	var resp map[string]interface{}
//	s.NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
//	s.Equal(float64(0), resp["total"])
//	s.IsType([]interface{}{}, resp["data"])
//}

//func (s *CVEHistorySuite) Test_InternalError() {
//	s.T().Skip()
//	s.handler.mockVerifyFunc = func(c echo.Context) (model.RequestHistorySearch, error) {
//		return model.RequestHistorySearch{Size: 10, Offset: 0}, nil
//	}
//
//	s.mocks.HistoryRepo.
//		On("Find", mock.Anything, mock.Anything, []string{"-created"}, 0, 10).
//		Return(nil, int64(0), errors.New("unexpected ES error"))
//
//	ctx, rec := createHistoryContext(s.e, http.MethodGet, "/CVE-2024-7777/history", nil)
//	err := s.handler.CVEHistory(ctx)
//
//	s.NoError(err)
//	s.Equal(http.StatusInternalServerError, rec.Code)
//}

// =========================
// Run Suite
// =========================

func TestCVEHistorySuite(t *testing.T) {
	suite.Run(t, new(CVEHistorySuite))
}
func TestCVEHandler_verifyCreate(t *testing.T) {
	tests := []struct {
		name           string
		inputBody      model.RequestCVECreate
		setupPatches   func() *gomonkey.Patches
		expectedError  bool
		errorContains  string
		validateResult func(t *testing.T, result model.RequestCVECreate)
	}{
		{
			name: "valid_request_all_fields",
			inputBody: model.RequestCVECreate{
				ID:          "CVE-2023-1234",
				Published:   1640995200,
				Match:       []string{"match1", "match2"},
				Description: "Test CVE description",
				Reference:   "https://example.com/ref",
				Patch:       "https://patch.com/fix",
				CVSS: model.CVSSMetric{
					CVSS3: model.CVEMetric{
						Score:        7.5,
						Version:      "3.1",
						Severity:     2,
						VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
					},
				},
				EPSS: &model.EPSSMetric{
					Score:      floatPtr(0.5),
					Percentile: floatPtr(0.8),
				},
				CWE: []model.CWEMetric{
					{
						ID:   "CWE-79",
						Name: "Cross-site Scripting",
						Link: "https://cwe.mitre.org/data/definitions/79.html",
					},
				},
				Lang: "en",
			},
			setupPatches: func() *gomonkey.Patches {
				patches := gomonkey.NewPatches()

				// Mock Validate function
				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					// Simulate parsing request body into the struct
					if reqBody, ok := body.(*model.RequestCVECreate); ok {
						// Copy data from context to the body struct
						// This simulates what the real Validate function does
						*reqBody = model.RequestCVECreate{
							ID:          "CVE-2023-1234",
							Published:   1640995200,
							Match:       []string{"match1", "match2"},
							Description: "Test CVE description",
							Reference:   "https://example.com/ref",
							Patch:       "https://patch.com/fix",
							CVSS: model.CVSSMetric{
								CVSS3: model.CVEMetric{
									Score:        7.5,
									Version:      "3.1",
									Severity:     2,
									VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
								},
							},
							EPSS: &model.EPSSMetric{
								Score:      floatPtr(0.5),
								Percentile: floatPtr(0.8),
							},
							CWE: []model.CWEMetric{
								{
									ID:   "CWE-79",
									Name: "Cross-site Scripting",
									Link: "https://cwe.mitre.org/data/definitions/79.html",
								},
							},
							Lang: "en",
						}
					}
					return nil
				})

				patches.ApplyFunc(validateCVEID, func(id string) (string, error) {
					return "CVE-2023-1234", nil
				})

				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) {
					return cvss, nil
				})

				patches.ApplyFunc(validateEPSS, func(epss *model.EPSSMetric) error {
					// Add nil check to prevent panic
					if epss == nil {
						return nil
					}
					return nil
				})

				patches.ApplyFunc(validateCWE, func(cwe []model.CWEMetric) ([]model.CWEMetric, error) {
					return cwe, nil
				})

				patches.ApplyFunc(validateLanguage, func(lang string) (string, error) {
					return "en", nil
				})

				return patches
			},
			expectedError: false,
			validateResult: func(t *testing.T, result model.RequestCVECreate) {
				assert.Equal(t, "CVE-2023-1234", result.ID)
				assert.Equal(t, "en", result.Lang)
				assert.Len(t, result.Match, 2, "Should have 2 match items")
				assert.Len(t, result.CWE, 1, "Should have 1 CWE item")
				assert.NotNil(t, result.EPSS, "EPSS should not be nil")
				if result.EPSS != nil {
					assert.Equal(t, 0.5, *result.EPSS.Score)
				}
			},
		},
		{
			name: "empty_match_should_initialize_empty_slice",
			inputBody: model.RequestCVECreate{
				ID:   "CVE-2023-5678",
				Lang: "en",
				// Match is nil/empty
			},
			setupPatches: func() *gomonkey.Patches {
				patches := gomonkey.NewPatches()

				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					if reqBody, ok := body.(*model.RequestCVECreate); ok {
						*reqBody = model.RequestCVECreate{
							ID:   "CVE-2023-5678",
							Lang: "en",
							// Match is intentionally nil here
						}
					}
					return nil
				})

				patches.ApplyFunc(validateCVEID, func(id string) (string, error) {
					return id, nil
				})

				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) {
					return cvss, nil
				})

				patches.ApplyFunc(validateEPSS, func(epss *model.EPSSMetric) error {
					return nil
				})

				patches.ApplyFunc(validateCWE, func(cwe []model.CWEMetric) ([]model.CWEMetric, error) {
					return cwe, nil
				})

				patches.ApplyFunc(validateLanguage, func(lang string) (string, error) {
					return lang, nil
				})

				return patches
			},
			expectedError: false,
			validateResult: func(t *testing.T, result model.RequestCVECreate) {
				assert.NotNil(t, result.Match, "Match should not be nil")
				assert.Empty(t, result.Match, "Match should be empty slice")
				assert.Equal(t, 0, len(result.Match))
			},
		},
		{
			name: "validate_function_returns_error",
			inputBody: model.RequestCVECreate{
				ID:   "",
				Lang: "",
			},
			setupPatches: func() *gomonkey.Patches {
				patches := gomonkey.NewPatches()
				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					return errors.New("validation failed: required fields missing")
				})
				return patches
			},
			expectedError: true,
			errorContains: "validation failed",
		},
		{
			name: "validateCVEID_returns_error",
			inputBody: model.RequestCVECreate{
				ID:   "INVALID-FORMAT",
				Lang: "en",
			},
			setupPatches: func() *gomonkey.Patches {
				patches := gomonkey.NewPatches()

				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					if reqBody, ok := body.(*model.RequestCVECreate); ok {
						*reqBody = model.RequestCVECreate{
							ID:   "INVALID-FORMAT",
							Lang: "en",
						}
					}
					return nil
				})

				patches.ApplyFunc(validateCVEID, func(id string) (string, error) {
					return "", errors.New("invalid CVE ID format: must match CVE-YYYY-NNNN")
				})

				return patches
			},
			expectedError: true,
			errorContains: "invalid CVE ID format",
		},
		{
			name: "validateCVSS_returns_error",
			inputBody: model.RequestCVECreate{
				ID:   "CVE-2023-1234",
				Lang: "en",
				CVSS: model.CVSSMetric{
					CVSS3: model.CVEMetric{Score: 15.0}, // Invalid score > 10
				},
			},
			setupPatches: func() *gomonkey.Patches {
				patches := gomonkey.NewPatches()

				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					if reqBody, ok := body.(*model.RequestCVECreate); ok {
						*reqBody = model.RequestCVECreate{
							ID:   "CVE-2023-1234",
							Lang: "en",
							CVSS: model.CVSSMetric{
								CVSS3: model.CVEMetric{Score: 15.0},
							},
						}
					}
					return nil
				})

				patches.ApplyFunc(validateCVEID, func(id string) (string, error) {
					return id, nil
				})

				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) {
					return cvss, errors.New("CVSS score must be between 0.0 and 10.0")
				})

				return patches
			},
			expectedError: true,
			errorContains: "CVSS score must be between",
		},
		{
			name: "validateEPSS_returns_error_with_safe_nil_check",
			inputBody: model.RequestCVECreate{
				ID:   "CVE-2023-1234",
				Lang: "en",
				EPSS: &model.EPSSMetric{
					Score:      floatPtr(1.5), // Invalid score > 1.0
					Percentile: floatPtr(0.8),
				},
			},
			setupPatches: func() *gomonkey.Patches {
				patches := gomonkey.NewPatches()

				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					if reqBody, ok := body.(*model.RequestCVECreate); ok {
						*reqBody = model.RequestCVECreate{
							ID:   "CVE-2023-1234",
							Lang: "en",
							EPSS: &model.EPSSMetric{
								Score:      floatPtr(1.5),
								Percentile: floatPtr(0.8),
							},
						}
					}
					return nil
				})

				patches.ApplyFunc(validateCVEID, func(id string) (string, error) {
					return id, nil
				})

				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) {
					return cvss, nil
				})

				patches.ApplyFunc(validateEPSS, func(epss *model.EPSSMetric) error {
					// Safe nil check
					if epss == nil {
						return nil
					}
					if epss.Score != nil && *epss.Score > 1.0 {
						return errors.New("EPSS score must be between 0.0 and 1.0")
					}
					return nil
				})

				return patches
			},
			expectedError: true,
			errorContains: "EPSS score must be between",
		},
		{
			name: "validateCWE_returns_error",
			inputBody: model.RequestCVECreate{
				ID:   "CVE-2023-1234",
				Lang: "en",
				CWE: []model.CWEMetric{
					{ID: "", Name: "", Link: ""}, // Invalid empty CWE
				},
			},
			setupPatches: func() *gomonkey.Patches {
				patches := gomonkey.NewPatches()

				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					if reqBody, ok := body.(*model.RequestCVECreate); ok {
						*reqBody = model.RequestCVECreate{
							ID:   "CVE-2023-1234",
							Lang: "en",
							CWE: []model.CWEMetric{
								{ID: "", Name: "", Link: ""},
							},
						}
					}
					return nil
				})

				patches.ApplyFunc(validateCVEID, func(id string) (string, error) {
					return id, nil
				})

				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) {
					return cvss, nil
				})

				patches.ApplyFunc(validateEPSS, func(epss *model.EPSSMetric) error {
					return nil
				})

				patches.ApplyFunc(validateCWE, func(cwe []model.CWEMetric) ([]model.CWEMetric, error) {
					return nil, errors.New("CWE validation failed: empty required fields")
				})

				return patches
			},
			expectedError: true,
			errorContains: "CWE validation failed",
		},
		{
			name: "validateLanguage_returns_error",
			inputBody: model.RequestCVECreate{
				ID:   "CVE-2023-1234",
				Lang: "xyz", // Invalid language code
			},
			setupPatches: func() *gomonkey.Patches {
				patches := gomonkey.NewPatches()

				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					if reqBody, ok := body.(*model.RequestCVECreate); ok {
						*reqBody = model.RequestCVECreate{
							ID:   "CVE-2023-1234",
							Lang: "xyz",
						}
					}
					return nil
				})

				patches.ApplyFunc(validateCVEID, func(id string) (string, error) {
					return id, nil
				})

				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) {
					return cvss, nil
				})

				patches.ApplyFunc(validateEPSS, func(epss *model.EPSSMetric) error {
					return nil
				})

				patches.ApplyFunc(validateCWE, func(cwe []model.CWEMetric) ([]model.CWEMetric, error) {
					return cwe, nil
				})

				patches.ApplyFunc(validateLanguage, func(lang string) (string, error) {
					return "", errors.New("unsupported language code: xyz")
				})

				return patches
			},
			expectedError: true,
			errorContains: "unsupported language",
		},
		{
			name: "multiple_validation_errors_sequence",
			inputBody: model.RequestCVECreate{
				ID:   "INVALID-ID",
				Lang: "invalid-lang",
			},
			setupPatches: func() *gomonkey.Patches {
				patches := gomonkey.NewPatches()

				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					if reqBody, ok := body.(*model.RequestCVECreate); ok {
						*reqBody = model.RequestCVECreate{
							ID:   "INVALID-ID",
							Lang: "invalid-lang",
						}
					}
					return nil
				})

				// First validation error should stop execution
				patches.ApplyFunc(validateCVEID, func(id string) (string, error) {
					return "", errors.New("invalid CVE ID format")
				})

				// These shouldn't be called due to early return
				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) {
					t.Error("validateCVSS should not be called when validateCVEID fails")
					return cvss, nil
				})

				return patches
			},
			expectedError: true,
			errorContains: "invalid CVE ID format",
		},
		{
			name: "edge_case_nil_epss_pointer",
			inputBody: model.RequestCVECreate{
				ID:   "CVE-2023-1234",
				Lang: "en",
				EPSS: nil, // Explicitly nil
			},
			setupPatches: func() *gomonkey.Patches {
				patches := gomonkey.NewPatches()

				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					if reqBody, ok := body.(*model.RequestCVECreate); ok {
						*reqBody = model.RequestCVECreate{
							ID:   "CVE-2023-1234",
							Lang: "en",
							EPSS: nil,
						}
					}
					return nil
				})

				patches.ApplyFunc(validateCVEID, func(id string) (string, error) {
					return id, nil
				})

				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) {
					return cvss, nil
				})

				patches.ApplyFunc(validateEPSS, func(epss *model.EPSSMetric) error {
					// Should handle nil gracefully
					if epss == nil {
						return nil
					}
					return nil
				})

				patches.ApplyFunc(validateCWE, func(cwe []model.CWEMetric) ([]model.CWEMetric, error) {
					return cwe, nil
				})

				patches.ApplyFunc(validateLanguage, func(lang string) (string, error) {
					return lang, nil
				})

				return patches
			},
			expectedError: false,
			validateResult: func(t *testing.T, result model.RequestCVECreate) {
				assert.Nil(t, result.EPSS, "EPSS should remain nil")
				assert.NotNil(t, result.Match, "Match should be initialized as empty slice")
			},
		},
		{
			name: "complex_error_scenario_cvss_and_cwe_both_fail",
			inputBody: model.RequestCVECreate{
				ID:   "CVE-2023-1234",
				Lang: "en",
				CVSS: model.CVSSMetric{
					CVSS3: model.CVEMetric{Score: -1.0}, // Invalid negative score
				},
				CWE: []model.CWEMetric{
					{ID: "INVALID-CWE", Name: "", Link: ""},
				},
			},
			setupPatches: func() *gomonkey.Patches {
				patches := gomonkey.NewPatches()

				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					if reqBody, ok := body.(*model.RequestCVECreate); ok {
						*reqBody = model.RequestCVECreate{
							ID:   "CVE-2023-1234",
							Lang: "en",
							CVSS: model.CVSSMetric{
								CVSS3: model.CVEMetric{Score: -1.0},
							},
							CWE: []model.CWEMetric{
								{ID: "INVALID-CWE", Name: "", Link: ""},
							},
						}
					}
					return nil
				})

				patches.ApplyFunc(validateCVEID, func(id string) (string, error) {
					return id, nil
				})

				// CVSS validation fails first, so execution stops here
				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) {
					return cvss, errors.New("CVSS score cannot be negative")
				})

				// This shouldn't be reached due to early return
				patches.ApplyFunc(validateEPSS, func(epss *model.EPSSMetric) error {
					return nil
				})

				patches.ApplyFunc(validateCWE, func(cwe []model.CWEMetric) ([]model.CWEMetric, error) {
					t.Error("validateCWE should not be called when validateCVSS fails")
					return cwe, nil
				})

				return patches
			},
			expectedError: true,
			errorContains: "CVSS score cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup patches
			patches := tt.setupPatches()
			defer patches.Reset()

			// Create handler
			handler := &CVEHandler{}

			// Create echo context with request body
			e := echo.New()
			bodyBytes, err := json.Marshal(tt.inputBody)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/cve", bytes.NewReader(bodyBytes))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Execute the method under test
			result, err := handler.verifyCreate(c)

			// Assertions
			if tt.expectedError {
				require.Error(t, err, "Expected error but got none")
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains,
						"Error message should contain expected substring")
				}
			} else {
				require.NoError(t, err, "Expected no error but got: %v", err)

				// Custom validation if provided
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

// Helper function
func floatPtr(f float64) *float64 {
	return &f
}

func TestCVEHandler_verifyEdit(t *testing.T) {
	tests := []struct {
		name           string
		inputBody      model.RequestCVEEdit
		setupPatches   func(t *testing.T) *gomonkey.Patches
		expectedError  bool
		errorContains  string
		validateResult func(t *testing.T, result model.RequestCVEEdit)
	}{
		{
			name:      "validate_function_returns_error",
			inputBody: model.RequestCVEEdit{},
			setupPatches: func(t *testing.T) *gomonkey.Patches {
				patches := gomonkey.NewPatches()
				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error {
					return errors.New("validation failed")
				})
				return patches
			},
			expectedError: true,
			errorContains: "validation failed",
		},
		{
			name:      "validateCVEID_returns_error",
			inputBody: model.RequestCVEEdit{ID: "INVALID-ID"},
			setupPatches: func(t *testing.T) *gomonkey.Patches {
				patches := gomonkey.NewPatches()
				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error { return nil })
				patches.ApplyFunc(validateCVEID, func(id string) (string, error) { return "", errors.New("invalid CVE ID") })
				return patches
			},
			expectedError: true,
			errorContains: "invalid CVE ID",
		},
		{
			name:      "empty_match_should_initialize_empty_slice",
			inputBody: model.RequestCVEEdit{ID: "CVE-2023-5678", Lang: "en"},
			setupPatches: func(t *testing.T) *gomonkey.Patches {
				patches := gomonkey.NewPatches()
				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error { return nil })
				patches.ApplyFunc(validateCVEID, func(id string) (string, error) { return id, nil })
				patches.ApplyFunc(hash.SHA1, func(s string) string { return s })
				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) { return cvss, nil })
				patches.ApplyFunc(validateEPSS, func(epss *model.EPSSMetric) error { return nil })
				patches.ApplyFunc(validateCWE, func(cwe []model.CWEMetric) ([]model.CWEMetric, error) { return cwe, nil })
				patches.ApplyFunc(validateLanguage, func(lang string) (string, error) { return lang, nil })
				return patches
			},
			expectedError: false,
			validateResult: func(t *testing.T, result model.RequestCVEEdit) {
				assert.NotNil(t, result.Match)
				assert.Empty(t, result.Match)
			},
		},
		{
			name: "validateCVSS_returns_error",
			inputBody: model.RequestCVEEdit{
				ID:   "CVE-2023-1234",
				Lang: "en",
				CVSS: model.CVSSMetric{CVSS3: model.CVEMetric{Score: 15.0}},
			},
			setupPatches: func(t *testing.T) *gomonkey.Patches {
				patches := gomonkey.NewPatches()
				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error { return nil })
				patches.ApplyFunc(validateCVEID, func(id string) (string, error) { return id, nil })
				patches.ApplyFunc(hash.SHA1, func(s string) string { return s })
				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) {
					return cvss, errors.New("CVSS score must be between 0.0 and 10.0")
				})
				return patches
			},
			expectedError: true,
			errorContains: "CVSS score must be between",
		},
		{
			name: "validateCWE_returns_error",
			inputBody: model.RequestCVEEdit{
				ID:   "CVE-2023-1234",
				Lang: "en",
				CWE:  []model.CWEMetric{{ID: "", Name: ""}},
			},
			setupPatches: func(t *testing.T) *gomonkey.Patches {
				patches := gomonkey.NewPatches()
				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error { return nil })
				patches.ApplyFunc(validateCVEID, func(id string) (string, error) { return id, nil })
				patches.ApplyFunc(hash.SHA1, func(s string) string { return s })
				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) { return cvss, nil })
				patches.ApplyFunc(validateEPSS, func(epss *model.EPSSMetric) error { return nil })
				patches.ApplyFunc(validateCWE, func(cwe []model.CWEMetric) ([]model.CWEMetric, error) {
					return nil, errors.New("CWE validation failed")
				})
				patches.ApplyFunc(validateLanguage, func(lang string) (string, error) { return lang, nil })
				return patches
			},
			expectedError: true,
			errorContains: "CWE validation failed",
		},
		{
			name:      "validateLanguage_returns_error",
			inputBody: model.RequestCVEEdit{ID: "CVE-2023-1234", Lang: "xyz"},
			setupPatches: func(t *testing.T) *gomonkey.Patches {
				patches := gomonkey.NewPatches()
				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error { return nil })
				patches.ApplyFunc(validateCVEID, func(id string) (string, error) { return id, nil })
				patches.ApplyFunc(hash.SHA1, func(s string) string { return s })
				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) { return cvss, nil })
				patches.ApplyFunc(validateEPSS, func(epss *model.EPSSMetric) error { return nil })
				patches.ApplyFunc(validateCWE, func(cwe []model.CWEMetric) ([]model.CWEMetric, error) { return cwe, nil })
				patches.ApplyFunc(validateLanguage, func(lang string) (string, error) { return "", errors.New("unsupported language code") })
				return patches
			},
			expectedError: true,
			errorContains: "unsupported language",
		},
		{
			name:      "edge_case_nil_epss_pointer",
			inputBody: model.RequestCVEEdit{ID: "CVE-2023-1234", Lang: "en", EPSS: nil},
			setupPatches: func(t *testing.T) *gomonkey.Patches {
				patches := gomonkey.NewPatches()
				patches.ApplyFunc(Validate, func(c echo.Context, body interface{}) error { return nil })
				patches.ApplyFunc(validateCVEID, func(id string) (string, error) { return id, nil })
				patches.ApplyFunc(hash.SHA1, func(s string) string { return s })
				patches.ApplyFunc(validateCVSS, func(cvss model.CVSSMetric) (model.CVSSMetric, error) { return cvss, nil })
				patches.ApplyFunc(validateEPSS, func(epss *model.EPSSMetric) error {
					if epss == nil {
						return nil
					}
					return nil
				})
				patches.ApplyFunc(validateCWE, func(cwe []model.CWEMetric) ([]model.CWEMetric, error) { return cwe, nil })
				patches.ApplyFunc(validateLanguage, func(lang string) (string, error) { return lang, nil })
				return patches
			},
			expectedError: false,
			validateResult: func(t *testing.T, result model.RequestCVEEdit) {
				assert.Nil(t, result.EPSS)
				assert.NotNil(t, result.Match)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patches := tt.setupPatches(t)
			defer patches.Reset()

			handler := &CVEHandler{}
			e := echo.New()
			bodyBytes, _ := json.Marshal(tt.inputBody)
			req := httptest.NewRequest(http.MethodPost, "/cve", bytes.NewReader(bodyBytes))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			result, err := handler.verifyEdit(c)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

func TestCVEHandler_GetThreatReport(t *testing.T) {
	type args struct {
		cveName  string
		response *model.CVEVerbose
	}

	// 1. Tạo mock repository
	mockReport := new(mockmg.ThreatReportRepository)
	// 2. Tạo mock Mongo trả về mockReport
	mockMongo := new(mockmg.GlobalRepository)
	mockMongo.On("ThreatReport").Return(mockReport)
	logger, _ := pencil.New(defs.HandlerCve, pencil.DebugLevel, true, os.Stdout)

	handler := &CVEHandler{
		mongo:  &mockmg.GlobalRepository{mockMongo.Mock},
		logger: logger,
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
		// để so sánh dữ liệu trả về
		wantVi   string
		wantEn   string
		wantSize int
		setMock  func()
	}{
		{
			name: "Success case (đủ cả vi và en)",
			args: args{
				cveName:  "CVE-2024-1234",
				response: &model.CVEVerbose{},
			},
			wantErr:  false,
			wantVi:   "Báo cáo tiếng Việt",
			wantEn:   "English Report",
			wantSize: 1,
			setMock: func() {
				mockReport.ExpectedCalls = nil
				mockReport.On("Find", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*model.ThreatReportAlert{
						{
							ApprovedTime: 1699999999,
							CodeReport:   "ABC-001",
							Multilang: map[string]interface{}{
								"vi": map[string]interface{}{
									"title": "Báo cáo tiếng Việt",
								},
								"en": map[string]interface{}{
									"title": "English Report",
								},
							},
						},
					}, nil)
			},
		},
		{
			name: "Chỉ có tiếng Việt, không tiếng Anh",
			args: args{
				cveName:  "CVE-2024-1235",
				response: &model.CVEVerbose{},
			},
			wantErr:  false,
			wantVi:   "Chỉ Việt",
			wantEn:   "",
			wantSize: 1,
			setMock: func() {
				mockReport.ExpectedCalls = nil
				mockReport.On("Find", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*model.ThreatReportAlert{
						{
							ApprovedTime: 1699999998,
							CodeReport:   "ABC-002",
							Multilang: map[string]interface{}{
								"vi": map[string]interface{}{
									"title": "Chỉ Việt",
								},
							},
						},
					}, nil)
			},
		},
		{
			name: "Chỉ có tiếng Anh, không tiếng Việt",
			args: args{
				cveName:  "CVE-2024-1236",
				response: &model.CVEVerbose{},
			},
			wantErr:  false,
			wantVi:   "",
			wantEn:   "Only English",
			wantSize: 1,
			setMock: func() {
				mockReport.ExpectedCalls = nil
				mockReport.On("Find", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*model.ThreatReportAlert{
						{
							ApprovedTime: 1699999997,
							CodeReport:   "ABC-003",
							Multilang: map[string]interface{}{
								"en": map[string]interface{}{
									"title": "Only English",
								},
							},
						},
					}, nil)
			},
		},
		{
			name: "Không có title trong multilang",
			args: args{
				cveName:  "CVE-2024-1237",
				response: &model.CVEVerbose{},
			},
			wantErr:  false,
			wantVi:   "",
			wantEn:   "",
			wantSize: 1,
			setMock: func() {
				mockReport.ExpectedCalls = nil
				mockReport.On("Find", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*model.ThreatReportAlert{
						{
							ApprovedTime: 1699999996,
							CodeReport:   "ABC-004",
							Multilang:    map[string]interface{}{},
						},
					}, nil)
			},
		},
		{
			name: "Title tiếng Việt sai kiểu",
			args: args{
				cveName:  "CVE-2024-1238",
				response: &model.CVEVerbose{},
			},
			wantErr:  false,
			wantVi:   "",
			wantEn:   "",
			wantSize: 1,
			setMock: func() {
				mockReport.ExpectedCalls = nil
				mockReport.On("Find", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*model.ThreatReportAlert{
						{
							ApprovedTime: 1699999995,
							CodeReport:   "ABC-005",
							Multilang: map[string]interface{}{
								"vi": map[string]interface{}{
									"title": 12345, // Sai kiểu
								},
							},
						},
					}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setMock != nil {
				tt.setMock()
			}
			err := handler.GetThreatReport(tt.args.cveName, tt.args.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetThreatReport() error = %v, wantErr %v", err, tt.wantErr)
			}

			if len(tt.args.response.ThreatReports) != tt.wantSize {
				t.Errorf("Expected %d report, got %d", tt.wantSize, len(tt.args.response.ThreatReports))
			} else {
				r := tt.args.response.ThreatReports[0]
				if r.ReportName.Vi != tt.wantVi {
					t.Errorf("Vi title: want '%s', got '%s'", tt.wantVi, r.ReportName.Vi)
				}
				if r.ReportName.En != tt.wantEn {
					t.Errorf("En title: want '%s', got '%s'", tt.wantEn, r.ReportName.En)
				}
			}
		})
	}

	mockReport.AssertExpectations(t)
}

type mockMongoRepo struct {
	threatReportRepo *mockmg.ThreatReportRepository
}

func (m *mockMongoRepo) ThreatReport() *mockmg.ThreatReportRepository {
	return m.threatReportRepo
}

func Test_getHistory(t *testing.T) {
	t.Skip()
	type args struct {
		body   model.RequestCVEConfirm
		saved  *model.CVE
		editor string
	}

	now, _ := clock.Now(clock.Local)
	savedModified := clock.UnixMilli(now)

	tests := []struct {
		name string
		args args
		want *model.History
	}{
		{
			name: "body.Status == defs.StatusCodeApproved and return nil",
			args: args{
				body: model.RequestCVEConfirm{
					Status:      defs.StatusCodeApproved,
					Description: "Approve CVE",
					Checklist: model.CVEChecklist{
						Metric: model.CVECheckListMetric{},
						Point:  9,
					},
				},
				saved: &model.CVE{
					ID:            "CVE-2025-0001",
					Status:        defs.StatusCodeApproved,
					ApprovedFirst: 0,
				},
				editor: "admin@example.com",
			},
			want: nil,
		},
		{
			name: "test case 2",
			args: args{
				body: model.RequestCVEConfirm{
					Status:      defs.StatusCodeReject,
					Description: "Approve CVE",
					Checklist: model.CVEChecklist{
						Metric: model.CVECheckListMetric{},
						Point:  9,
					},
				},
				saved: &model.CVE{
					ID:            "CVE-2025-0001",
					Status:        defs.StatusCodeApproved,
					ApprovedFirst: 0,
				},
				editor: "admin@example.com",
			},
			want: &model.History{ID: "", Created: savedModified, Document: "CVE-2025-0001", Editor: "admin@example.com", Action: "Reject CVE", Description: "Approve CVE", HistoryType: "system"},
		},
		{
			name: "test case 3",
			args: args{
				body: model.RequestCVEConfirm{
					Status:      defs.StatusCodeApproved,
					Description: "Approve CVE",
					Checklist: model.CVEChecklist{
						Metric: model.CVECheckListMetric{},
						Point:  9,
					},
				},
				saved: &model.CVE{
					ID:            "CVE-2025-0001",
					Status:        defs.StatusCodeApproved,
					ApprovedFirst: 1,
					Checklist: model.CVEChecklist{
						Metric: model.CVECheckListMetric{Affect: 1},
					},
				},
				editor: "admin@example.com",
			},
			want: &model.History{ID: "", Created: savedModified, Document: "CVE-2025-0001", Editor: "admin@example.com", Action: "Edit Checklist", Description: "Approve CVE", HistoryType: "system"},
		},
		{
			name: "test case 4",
			args: args{
				body: model.RequestCVEConfirm{
					Status:      defs.StatusCodeApproved,
					Description: "Approve CVE",
					Checklist: model.CVEChecklist{
						Metric: model.CVECheckListMetric{},
						Point:  9,
					},
				},
				saved: &model.CVE{
					ID:            "CVE-2025-0001",
					Status:        defs.StatusCodeReject,
					ApprovedFirst: 0,
				},
				editor: "admin@example.com",
			},

			want: &model.History{ID: "", Created: savedModified, Document: "CVE-2025-0001", Editor: "admin@example.com", Action: "Approve CVE", Description: "Approve CVE", HistoryType: "system"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getHistory(tt.args.body, tt.args.saved, tt.args.editor)

			if tt.want == nil {
				if got != nil {
					t.Errorf("getHistory() = %+v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Errorf("getHistory() = nil, want %+v", tt.want)
				return
			}

			if got.Action != tt.want.Action ||
				got.Editor != tt.want.Editor ||
				got.Description != tt.want.Description ||
				got.Document != tt.want.Document ||
				got.HistoryType != tt.want.HistoryType {
				t.Errorf("getHistory() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDeleteCveCustomer(t *testing.T) {
	tests := []struct {
		name      string
		data      map[string]struct{}
		cveID     string
		mockSetup func(mockCve *mocks.MockCVECustomerRepository)
		expectErr bool
	}{
		{
			name:  "empty data returns nil",
			data:  map[string]struct{}{},
			cveID: "cve-123",
			mockSetup: func(mockCve *mocks.MockCVECustomerRepository) {
				// không gọi gì
			},
			expectErr: false,
		},
		{
			name:  "success with multiple tenants",
			data:  map[string]struct{}{"tenant1": {}, "tenant2": {}},
			cveID: "cve-123",
			mockSetup: func(mockCve *mocks.MockCVECustomerRepository) {
				mockCve.EXPECT().
					BulkDelete(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(2)
			},
			expectErr: false,
		},
		{
			name:  "bulk delete fails",
			data:  map[string]struct{}{"tenant1": {}},
			cveID: "cve-123",
			mockSetup: func(mockCve *mocks.MockCVECustomerRepository) {
				mockCve.EXPECT().
					BulkDelete(gomock.Any(), gomock.Any()).
					Return(errors.New("delete failed")).
					Times(1)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockCveRepo := mocks.NewMockCVECustomerRepository(ctrl)
			tt.mockSetup(mockCveRepo)

			mockEnrichment := mocks.NewMockEnrichmentRepository(ctrl)
			mockEnrichment.EXPECT().CVECustomer().Return(mockCveRepo).AnyTimes()

			mockElastic := mocks.NewMockGlobalRepository(ctrl)
			mockElastic.EXPECT().Enrichment().Return(mockEnrichment).AnyTimes()

			handler := &CVEHandler{
				elastic: mockElastic,
			}

			err := handler.deleteCveCustomer(context.Background(), tt.data, tt.cveID)

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBulkInsertCveCustomer(t *testing.T) {
	tests := []struct {
		name      string
		data      []model.Organization
		cveID     string
		mockSetup func(m *mocks.MockCVECustomerRepository)
		expectErr bool
	}{
		{
			name:  "no duplicates → bulk insert",
			data:  []model.Organization{{TenantId: "tenantX"}},
			cveID: "cve-123",
			mockSetup: func(m *mocks.MockCVECustomerRepository) {
				m.EXPECT().
					Find(gomock.Any(), gomock.Any()).
					Return([]*model.CveCustomer{}, nil).Times(1)

				m.EXPECT().
					BulkInsert(gomock.Any(), gomock.Any()).
					Return(nil).Times(1)
			},
			expectErr: false,
		},
		{
			name:  "repository Find() error",
			data:  []model.Organization{{TenantId: "tenantX"}},
			cveID: "cve-123",
			mockSetup: func(m *mocks.MockCVECustomerRepository) {
				m.EXPECT().
					Find(gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("db error")).Times(1)

			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockCveRepo := mocks.NewMockCVECustomerRepository(ctrl)
			tt.mockSetup(mockCveRepo)

			mockEnrichment := mocks.NewMockEnrichmentRepository(ctrl)
			mockEnrichment.EXPECT().CVECustomer().Return(mockCveRepo).AnyTimes()

			mockElastic := mocks.NewMockGlobalRepository(ctrl)
			mockElastic.EXPECT().Enrichment().Return(mockEnrichment).AnyTimes()

			handler := &CVEHandler{
				elastic: mockElastic,
			}

			err := handler.bulkInsertCveCustomer(context.Background(), tt.data, tt.cveID)

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetDiffOrganizations(t *testing.T) {
	tests := []struct {
		name     string
		oldData  []model.Organization
		newData  []string
		expected []string
	}{
		{
			name:     "no old data, all new",
			oldData:  []model.Organization{},
			newData:  []string{"t1", "t2"},
			expected: []string{"t1", "t2"},
		},
		{
			name: "some overlap, only diff returned",
			oldData: []model.Organization{
				{TenantId: "t1"},
			},
			newData:  []string{"t1", "t2"},
			expected: []string{"t2"},
		},
		{
			name: "all already exist",
			oldData: []model.Organization{
				{TenantId: "t1"},
				{TenantId: "t2"},
			},
			newData:  []string{"t1", "t2"},
			expected: []string{},
		},
		{
			name:     "empty input",
			oldData:  []model.Organization{},
			newData:  []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getDiffOrganinations(tt.oldData, tt.newData)
			if len(got) != len(tt.expected) {
				t.Fatalf("expected %d orgs, got %d", len(tt.expected), len(got))
			}
			for i, exp := range tt.expected {
				if got[i].TenantId != exp {
					t.Errorf("expected TenantId %s, got %s", exp, got[i].TenantId)
				}
				if got[i].ApprovalTime == 0 {
					t.Error("expected ApprovalTime to be set > 0, got 0")
				}
				now := time.Now().UnixMilli()
				if got[i].ApprovalTime > now || got[i].ApprovalTime < now-1000 {
					t.Errorf("unexpected ApprovalTime range: %d", got[i].ApprovalTime)
				}
			}
		})
	}
}

func TestCreateLifecycle(t *testing.T) {
	tests := []struct {
		name      string
		document  *model.CVE
		setupMock func(mockRepo *mocks.MockCVELifecycleRepository)
		wantErr   bool
	}{
		{
			name:     "successfully stores lifecycle",
			document: &model.CVE{ID: "cve-123", Name: "CVE-2025-0001"},
			setupMock: func(mockRepo *mocks.MockCVELifecycleRepository) {
				mockRepo.EXPECT().
					Store(gomock.Any(), gomock.Any()).
					Return(nil)
			},
			wantErr: false,
		},
		{
			name:     "store returns error",
			document: &model.CVE{ID: "cve-999", Name: "CVE-ERROR"},
			setupMock: func(mockRepo *mocks.MockCVELifecycleRepository) {
				mockRepo.EXPECT().
					Store(gomock.Any(), gomock.Any()).
					Return(assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockRepo := mocks.NewMockCVELifecycleRepository(ctrl)
			tt.setupMock(mockRepo)

			mockEnrichment := mocks.NewMockEnrichmentRepository(ctrl)
			mockElastic := mocks.NewMockGlobalRepository(ctrl)

			mockEnrichment.EXPECT().CVELifecycle().Return(mockRepo).AnyTimes()
			mockElastic.EXPECT().Enrichment().Return(mockEnrichment).AnyTimes()

			h := &CVEHandler{elastic: mockElastic}
			req := &model.CVELifecycle{}

			err := h.createLifecycle(tt.document, req)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.document.ID, req.CVEId)
				require.Equal(t, tt.document.Name, req.CVECode)
				require.NotZero(t, req.Created)

				now := time.Now().UnixMilli()
				assert.InDelta(t, now, req.Created, 2000)
			}
		})
	}
}

func TestGetHistory_TableDriven(t *testing.T) {
	editor := "tester"
	metric1 := model.CVECheckListMetric{Affect: 1, Exploit: 1, Patch: 0, Ability: 0, Condition: 0}
	metric2 := model.CVECheckListMetric{Affect: 2, Exploit: 1, Patch: 0, Ability: 0, Condition: 0}
	tests := []struct {
		name       string
		saved      *model.CVE
		body       model.RequestCVEConfirm
		wantNil    bool
		wantAction string
		verify     func(*testing.T, *model.CVE, *model.History)
	}{
		{
			name: "Approve lần đầu khi saved.Status = Approved và saved.Approved = 0",
			saved: &model.CVE{
				ID:       "cve-20",
				Status:   defs.StatusCodeApproved,
				Score:    model.CVEScore{},
				Approved: 0,
				History:  []model.SeverityMetric{},
			},
			body: model.RequestCVEConfirm{
				Status:      defs.StatusCodeApproved,
				Description: "approve lần đầu vào switch",
				Checklist: model.CVEChecklist{
					Metric: metric1,
					Point:  10,
				},
			},
			wantNil:    false,
			wantAction: defs.ActionApproveCVE,
			verify: func(t *testing.T, saved *model.CVE, h *model.History) {
				assert.NotZero(t, saved.Approved)
				assert.Equal(t, saved.Approved, saved.ApprovedFirst)
				if assert.NotEmpty(t, saved.History) {
					last := saved.History[len(saved.History)-1]
					assert.Equal(t, defs.HistorySeverityNewType, last.Type)
				}
			},
		},
		{
			name: "Approve update metric khác",
			saved: &model.CVE{
				ID:       "cve-2",
				Status:   defs.StatusCodeApproved,
				Approved: 1111,
				Checklist: model.CVEChecklist{
					Metric: metric1,
				},
				Score: model.CVEScore{},
			},
			body: model.RequestCVEConfirm{
				Status:      defs.StatusCodeApproved,
				Description: "update metric",
				Checklist: model.CVEChecklist{
					Metric: metric2,
					Point:  20,
				},
			},
			wantNil:    false,
			wantAction: defs.ActionApproveCVE,
			verify: func(t *testing.T, saved *model.CVE, h *model.History) {
				last := saved.History[len(saved.History)-1]
				assert.Equal(t, defs.HistorySeverityUpdateType, last.Type)
			},
		},
		{
			name: "Approve metric không đổi → return nil",
			saved: &model.CVE{
				ID:     "cve-3",
				Status: defs.StatusCodeApproved,
				Checklist: model.CVEChecklist{
					Metric: metric1,
				},
				Score: model.CVEScore{},
			},
			body: model.RequestCVEConfirm{
				Status:      defs.StatusCodeApproved,
				Description: "no change",
				Checklist: model.CVEChecklist{
					Metric: metric1,
					Point:  10,
				},
			},
			wantNil: true,
		},
		{
			name: "Update status thành Approved → set Approved = nowMilli",
			saved: &model.CVE{
				ID:       "cve-30",
				Status:   defs.StatusCodeNew,
				Approved: 0,
				Score:    model.CVEScore{},
			},
			body: model.RequestCVEConfirm{
				Status:      defs.StatusCodeApproved,
				Description: "update thành approved",
				Checklist: model.CVEChecklist{
					Metric: metric1,
					Point:  99,
				},
			},
			wantNil:    false,
			wantAction: defs.ActionApproveCVE,
			verify: func(t *testing.T, saved *model.CVE, h *model.History) {
				assert.NotZero(t, saved.Approved)
				assert.Equal(t, "update thành approved", saved.ReasonChangeStatus)
				assert.Equal(t, defs.StatusCodeApproved, saved.Status)
			},
		},
		{
			name: "Reject từ trạng thái Approved",
			saved: &model.CVE{
				ID:       "cve-10",
				Status:   defs.StatusCodeApproved,
				Approved: 12345,
				Score:    model.CVEScore{},
			},
			body: model.RequestCVEConfirm{
				Status:      defs.StatusCodeReject,
				Description: "reject sau khi approved",
			},
			wantNil:    false,
			wantAction: defs.ActionRejectCVE,
			verify: func(t *testing.T, saved *model.CVE, h *model.History) {
				assert.Equal(t, defs.StatusCodeReject, saved.Status)
				assert.Equal(t, int64(0), saved.Approved)
			},
		},
		{
			name: "Reject từ trạng thái New",
			saved: &model.CVE{
				ID:     "cve-11",
				Status: defs.StatusCodeNew,
				Score:  model.CVEScore{},
			},
			body: model.RequestCVEConfirm{
				Status:      defs.StatusCodeReject,
				Description: "reject từ new",
			},
			wantNil:    false,
			wantAction: defs.ActionRejectCVE,
			verify: func(t *testing.T, saved *model.CVE, h *model.History) {
				assert.Equal(t, defs.StatusCodeReject, saved.Status)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			his := getHistory(tt.body, tt.saved, editor)

			if tt.wantNil {
				assert.Nil(t, his)
			} else {
				assert.NotNil(t, his)
				assert.Equal(t, tt.wantAction, his.Action)
				assert.Equal(t, editor, his.Editor)
				assert.Equal(t, tt.body.Description, his.Description)
				if tt.verify != nil {
					tt.verify(t, tt.saved, his)
				}
			}
		})
	}
}

func TestValidateCVSS_Table(t *testing.T) {
	tests := []struct {
		name      string
		cvss      model.CVSSMetric
		wantError bool
		errMsg    string
	}{
		{
			name: "all fields empty",
			cvss: model.CVSSMetric{},
		},
		{
			name:      "invalid CVSS2 version",
			cvss:      model.CVSSMetric{CVSS2: model.CVEMetric{Version: "2.1"}},
			wantError: true,
			errMsg:    "invalid CVSS v2 version: 2.1",
		},
		{
			name:      "invalid CVSS3 version",
			cvss:      model.CVSSMetric{CVSS3: model.CVEMetric{Version: "3.5"}},
			wantError: true,
			errMsg:    "invalid CVSS v3 version: 3.5",
		},
		{
			name:      "invalid CVSS4 version",
			cvss:      model.CVSSMetric{CVSS4: model.CVEMetric{Version: "4.1"}},
			wantError: true,
			errMsg:    "invalid CVSS v4 version: 4.1",
		},
		{
			name:      "invalid CNA version",
			cvss:      model.CVSSMetric{CNA: model.CVEMetric{Version: "5.0"}},
			wantError: true,
			errMsg:    "invalid CNA CVSS version: 5.0 (supported: 2.0, 3.0, 3.1, 4.0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateCVSS(tt.cvss)

			if tt.wantError {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.errMsg)
			} else {
				assert.NoError(t, err)
				_ = got
			}
		})
	}
}

func TestValidateCVEMetric(t *testing.T) {
	validVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // hợp lệ
	tests := []struct {
		name       string
		input      model.CVEMetric
		versionStd string
		fieldName  string
		wantError  bool
		errMsg     string
		wantScore  float32
		wantSource string
	}{
		{
			name:       "all fields empty → valid",
			input:      model.CVEMetric{},
			versionStd: defs.VersionCvssV31,
			fieldName:  "cna",
		},
		{
			name: "missing version but has vectorString → error",
			input: model.CVEMetric{
				VectorString: validVector,
			},
			versionStd: defs.VersionCvssV31,
			fieldName:  "cna",
			wantError:  true,
			errMsg:     "cna: must provide all fields: version",
		},
		{
			name: "score < 0 → error",
			input: model.CVEMetric{
				Version: "3.1",
				Score:   -1.0,
				Source:  defs.SourceCvssNvd,
			},
			versionStd: defs.VersionCvssV31,
			fieldName:  "cna",
			wantError:  true,
			errMsg:     "invalid value for cna.score",
		},
		{
			name: "score > 10 → error",
			input: model.CVEMetric{
				Version: "3.1",
				Score:   11.1,
				Source:  defs.SourceCvssNvd,
			},
			versionStd: defs.VersionCvssV31,
			fieldName:  "cna",
			wantError:  true,
			errMsg:     "invalid value for cna.score",
		},
		{
			name: "valid score gets rounded, source nvd",
			input: model.CVEMetric{
				Version:      "3.1",
				Score:        6.94,
				VectorString: validVector,
				Source:       "nvd", // lowercase
			},
			versionStd: defs.VersionCvssV31,
			fieldName:  "cna",
			wantScore:  6.9,
			wantSource: defs.SourceCvssNvd,
		},
		{
			name: "invalid source → error",
			input: model.CVEMetric{
				Version:      "3.1",
				Score:        5.0,
				VectorString: validVector,
				Source:       "random",
			},
			versionStd: defs.VersionCvssV31,
			fieldName:  "cna",
			wantError:  true,
			errMsg:     "cna.source must be either 'nvd' or 'cna'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateCVEMetric(tt.input, tt.versionStd, tt.fieldName)

			if tt.wantError {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.errMsg)
			} else {
				assert.NoError(t, err)
				if tt.wantScore != 0 {
					assert.InDelta(t, tt.wantScore, got.Score, 0.01)
				}
				if tt.wantSource != "" {
					assert.Equal(t, tt.wantSource, got.Source)
				}
			}
		})
	}
}

func TestSliceContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected bool
	}{
		{
			name:     "item exists in slice",
			slice:    []string{"a", "b", "c"},
			item:     "b",
			expected: true,
		},
		{
			name:     "item does not exist in slice",
			slice:    []string{"a", "b", "c"},
			item:     "x",
			expected: false,
		},
		{
			name:     "empty slice",
			slice:    []string{},
			item:     "a",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sliceContains(tt.slice, tt.item)
			if got != tt.expected {
				t.Errorf("sliceContains(%v, %s) = %v; want %v", tt.slice, tt.item, got, tt.expected)
			}
		})
	}
}

func TestFilterTags(t *testing.T) {
	tests := []struct {
		name         string
		tags         []string
		tagsToRemove []string
		expected     []string
	}{
		{
			name:         "remove one tag",
			tags:         []string{"a", "b", "c"},
			tagsToRemove: []string{"b"},
			expected:     []string{"a", "c"},
		},
		{
			name:         "remove multiple tags",
			tags:         []string{"a", "b", "c", "d"},
			tagsToRemove: []string{"a", "d"},
			expected:     []string{"b", "c"},
		},
		{
			name:         "no tags removed",
			tags:         []string{"a", "b"},
			tagsToRemove: []string{"x", "y"},
			expected:     []string{"a", "b"},
		},
		{
			name:         "empty tagsToRemove list",
			tags:         []string{"a", "b"},
			tagsToRemove: []string{},
			expected:     []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterTags(tt.tags, tt.tagsToRemove)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("filterTags(%v, %v) = %v; want %v",
					tt.tags, tt.tagsToRemove, got, tt.expected)
			}
		})
	}
}

func TestValidateCWE(t *testing.T) {
	tests := []struct {
		name      string
		input     []model.CWEMetric
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "empty array returns nil error",
			input:   []model.CWEMetric{},
			wantErr: false,
		},
		{
			name: "missing ID",
			input: []model.CWEMetric{
				{ID: " ", Name: "Buffer Overflow", Link: "http://cwe.mitre.org"},
			},
			wantErr:   true,
			errSubstr: "CWE ID is required for item 1",
		},
		{
			name: "invalid CWE ID format",
			input: []model.CWEMetric{
				{ID: "Invalid-123", Name: "Buffer Overflow", Link: "http://cwe.mitre.org"},
			},
			wantErr:   true,
			errSubstr: "invalid CWE ID format for item 1",
		},
		{
			name: "missing link",
			input: []model.CWEMetric{
				{ID: "CWE-79", Name: "XSS", Link: "   "},
			},
			wantErr:   true,
			errSubstr: "link is required for item 1",
		},
		{
			name: "duplicate CWE ID",
			input: []model.CWEMetric{
				{ID: "CWE-79", Name: "XSS", Link: "http://cwe.mitre.org/data/79.html"},
				{ID: "CWE-79", Name: "Duplicate XSS", Link: "http://cwe.mitre.org/data/79-dup.html"},
			},
			wantErr:   true,
			errSubstr: "duplicate CWE ID: CWE-79 at item 2",
		},
		{
			name: "valid single CWE",
			input: []model.CWEMetric{
				{ID: " CWE-89 ", Name: " SQL Injection ", Link: " http://cwe.mitre.org/data/89.html "},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateCWE(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errSubstr)
			} else {
				require.NoError(t, err, "did not expect error but got: %v", err)
				if len(got) > 0 {
					require.Equal(t, "CWE-89", got[0].ID, "ID should be trimmed")
					require.Equal(t, "SQL Injection", got[0].Name, "Name should be trimmed")
					require.Equal(t, "http://cwe.mitre.org/data/89.html", got[0].Link, "Link should be trimmed")
				}
			}
		})
	}
}

func TestConvertCPEFormat(t *testing.T) {
	tests := []struct {
		name      string
		cpe       string
		want      *model.CPE
		wantPanic bool
	}{
		{
			name: "Valid CPE string (all fields)",
			cpe:  "cpe:2.3:a:vendor:product:1.0:update:edition:lang:swEdition:targetSw:targetHw:other",
			want: &model.CPE{
				CPEDetail: model.CPEDetail{
					Value:   "cpe:2.3:a:vendor:product:1.0:update:edition:lang:swEdition:targetSw:targetHw:other",
					Part:    "a",
					Vendor:  "vendor",
					Product: "product",
					Version: "1.0",
					Update:  "update",
				},
				Edition:   "edition",
				Language:  "lang",
				SwEdition: "swEdition",
				TargetSw:  "targetSw",
				TargetHw:  "targetHw",
				Other:     "other",
			},
		},
		{
			name:      "Short CPE string (panic expected)",
			cpe:       "cpe:2.3:a:vendor",
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				require.Panics(t, func() {
					ConvertCPEFormat(tt.cpe)
				})
				return
			}

			got := ConvertCPEFormat(tt.cpe)
			require.Equal(t, tt.want.CPEDetail.Value, got.CPEDetail.Value)
			require.Equal(t, tt.want.Part, got.Part)
			require.Equal(t, tt.want.Vendor, got.Vendor)
			require.Equal(t, tt.want.Product, got.Product)
			require.Equal(t, tt.want.Version, got.Version)
			require.Equal(t, tt.want.Update, got.Update)
			require.Equal(t, tt.want.Edition, got.Edition)
			require.Equal(t, tt.want.Language, got.Language)
			require.Equal(t, tt.want.SwEdition, got.SwEdition)
			require.Equal(t, tt.want.TargetSw, got.TargetSw)
			require.Equal(t, tt.want.TargetHw, got.TargetHw)
			require.Equal(t, tt.want.Other, got.Other)
		})
	}
}

func TestVerifySearchFilter(t *testing.T) {
	tests := []struct {
		name    string
		body    model.RequestCVESearch
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Empty request -> default ok",
			body:    model.RequestCVESearch{},
			wantErr: false,
		},
		{
			name: "Sort fields should be appended when time filters set",
			body: model.RequestCVESearch{
				Time: model.CVESearchTime{
					Approved:     model.RangeInt64{Gte: 1},
					Modified:     model.RangeInt64{Lte: 2},
					AnalysisTime: model.RangeInt64{Gte: 3, Lte: 4},
				},
			},
			wantErr: false,
		},
		{
			name: "Keyword and Checker normalize",
			body: model.RequestCVESearch{
				Keyword: "   KeyWord   ",
				Checker: "CHECKer",
			},
			wantErr: false,
		},
		{
			name: "Invalid VTI.Version",
			body: model.RequestCVESearch{
				Severity: model.RequestCVESeverity{
					VTI: model.RequestCVESeverityVerbose{
						Version: "invalid",
						Value:   []int{1},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid value for param <severity.vti.version>",
		},
		{
			name: "Invalid Global.Version item",
			body: model.RequestCVESearch{
				Severity: model.RequestCVESeverity{
					Global: model.RequestCVESeverityVerboseV2{
						Version: []string{"wrong"},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid value for param <severity.global.version>",
		},
		{
			name: "Invalid Languages entry",
			body: model.RequestCVESearch{
				Languages: []string{"xyz"},
			},
			wantErr: true,
			errMsg:  "invalid value for param <languages>",
		},
		{
			name: "Invalid Approved range",
			body: model.RequestCVESearch{
				Time: model.CVESearchTime{
					Approved: model.RangeInt64{Gte: 5, Lte: 3},
				},
			},
			wantErr: true,
			errMsg:  "invalid value for param <time.approved.gte>",
		},
		{
			name: "Invalid Modified range",
			body: model.RequestCVESearch{
				Time: model.CVESearchTime{
					Modified: model.RangeInt64{Gte: 10, Lte: 1},
				},
			},
			wantErr: true,
			errMsg:  "invalid value for param <time.modified.gte>",
		},
		{
			name: "Invalid AnalysisTime range",
			body: model.RequestCVESearch{
				Time: model.CVESearchTime{
					AnalysisTime: model.RangeInt64{Gte: 20, Lte: 5},
				},
			},
			wantErr: true,
			errMsg:  "invalid value for param <time.modified.gte>", // trong code reuse msg
		},
		{
			name: "Valid with languages",
			body: model.RequestCVESearch{
				Languages: []string{"en"},
			},
			wantErr: false,
		},
	}

	h := &CVEHandler{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.verifySearchFilter(tt.body)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.True(t, strings.Contains(err.Error(), tt.errMsg))
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

type fakeLogger struct{}

func (f *fakeLogger) Infof(_ string, _ ...interface{}) {}

type fakeHandler struct {
	CVEHandler
	bulkErr error
}

func (f *fakeHandler) BulkInsertCveCustomer(ctx context.Context, orgs []model.Organization, name string) error {
	return f.bulkErr
}

func (f *fakeHandler) bulkInsertCveCustomer(ctx context.Context, orgs []model.Organization, name string) error {
	// chú ý: method này cần tên trùng với method gốc trong CVEHandler để override
	return f.bulkErr
}

func TestProcessCveCustomer(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name          string
		status        int
		bulkErr       error
		wantErr       bool
		organizations []model.Organization
		customers     []string
	}{
		{
			name:          "not approved → should return nil",
			status:        defs.StatusCodeUnknown,
			bulkErr:       nil,
			wantErr:       false,
			organizations: []model.Organization{{TenantId: "org1"}},
			customers:     []string{"org2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &fakeHandler{bulkErr: tt.bulkErr}
			h.logger = nil

			cve := &model.CVE{
				Status:        tt.status,
				Name:          "CVE-123",
				Organizations: tt.organizations,
				Customer:      tt.customers,
			}
			err := h.processCveCustomer(ctx, cve)
			if tt.wantErr {
				require.Error(t, err, "expect error but got nil")
			} else {
				require.NoError(t, err, "expect no error but got: %v", err)
			}
		})
	}
}

func TestGetCPE(t *testing.T) {
	tests := []struct {
		name      string
		match     []string
		setupMock func(mockCPE *mocks.MockCPERepository)
		wantLen   int
		wantErr   bool
	}{
		{
			name:  "success found in repo",
			match: []string{"pro1"},
			setupMock: func(mockCPE *mocks.MockCPERepository) {
				mockCPE.EXPECT().
					FindByValue(gomock.Any(), "pro1").
					Return(&model.CPE{
						CPEDetail: model.CPEDetail{
							Part:    "a",
							Version: "1.0",
							ID:      "id-1",
							Value:   "pro1",
						},
						Name: "pro1-name",
					}, nil)
			},
			wantLen: 1,
			wantErr: false,
		},
		{
			name:  "db error -> return error",
			match: []string{"pro3"},
			setupMock: func(mockCPE *mocks.MockCPERepository) {
				mockCPE.EXPECT().
					FindByValue(gomock.Any(), "pro3").
					Return(nil, errors.New("db error"))
			},
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockCPE := mocks.NewMockCPERepository(ctrl)
			mockEnrichment := mocks.NewMockEnrichmentRepository(ctrl)
			mockElastic := mocks.NewMockGlobalRepository(ctrl)

			if tt.setupMock != nil {
				tt.setupMock(mockCPE)
			}

			// wiring mocks
			mockEnrichment.EXPECT().CPE().Return(mockCPE).AnyTimes()
			mockElastic.EXPECT().Enrichment().Return(mockEnrichment).AnyTimes()

			h := &CVEHandler{elastic: mockElastic}

			got, err := h.GetCPE(tt.match)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Len(t, got, tt.wantLen)
			}
		})
	}
}

func TestValidateListID(t *testing.T) {
	tests := []struct {
		name string
		ids  []string
		want []string
	}{
		{
			name: "empty input",
			ids:  []string{},
			want: []string{},
		},
		{
			name: "all empty or spaces",
			ids:  []string{"", " ", "   "},
			want: []string{},
		},
		{
			name: "valid without spaces",
			ids:  []string{"abc", "def"},
			want: []string{"abc", "def"},
		},
		{
			name: "valid with spaces around",
			ids:  []string{" abc ", " def "},
			want: []string{"abc", "def"},
		},
		{
			name: "mixed valid and invalid",
			ids:  []string{"abc", " ", "", " xyz "},
			want: []string{"abc", "xyz"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateListID(tt.ids)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("validateListID(%v) = %v, want %v", tt.ids, got, tt.want)
			}
		})
	}
}

func TestGetGreatestVersionFilter(t *testing.T) {
	cases := []struct {
		name        string
		versions    []string
		wantVersion string
		wantFilter  bool
	}{
		{
			name:        "Co CVSSv4",
			versions:    []string{defs.VersionCvssV3, defs.VersionCvssV4},
			wantVersion: defs.VersionCvssV4,
			wantFilter:  true,
		},
		{
			name:        "Chỉ có CVSSv3",
			versions:    []string{defs.VersionCvssV3},
			wantVersion: defs.VersionCvssV3,
			wantFilter:  true,
		},
		{
			name:        "Chỉ có CVSSv2",
			versions:    []string{defs.VersionCvssV2},
			wantVersion: defs.VersionCvssV2,
			wantFilter:  true,
		},
		{
			name:        "Không có version hợp lệ",
			versions:    []string{"unknown"},
			wantVersion: "",
			wantFilter:  false,
		},
		{
			name:        "Input rỗng",
			versions:    []string{},
			wantVersion: "",
			wantFilter:  false,
		},
		{
			name:        "Có cả CVSSv3 và CVSSv2 (ưu tiên CVSSv3)",
			versions:    []string{defs.VersionCvssV3, defs.VersionCvssV2},
			wantVersion: defs.VersionCvssV3,
			wantFilter:  true,
		},
		{
			name:        "Có cả 3 phiên bản (ưu tiên lớn nhất)",
			versions:    []string{defs.VersionCvssV2, defs.VersionCvssV3, defs.VersionCvssV4},
			wantVersion: defs.VersionCvssV4,
			wantFilter:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			version, filter := getGreatestVersionFilter(tc.versions)
			assert.Equal(t, tc.wantVersion, version)
			assert.Equal(t, tc.wantFilter, filter)
		})
	}
}

func TestVerifySearchInternalFlag(t *testing.T) {
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}
	tests := []struct {
		name        string
		body        string
		wantErr     bool
		wantKeyword string
	}{
		{
			name:    "invalid body (wrong type)",
			body:    `{"keyword":123}`,
			wantErr: true,
		},
		{
			name:        "valid body with spaces",
			body:        `{"keyword":"   hello  "}`,
			wantErr:     false,
			wantKeyword: "hello",
		},
		{
			name:        "valid body clean keyword",
			body:        `{"keyword":"world"}`,
			wantErr:     false,
			wantKeyword: "world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", strings.NewReader(tt.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			h := &CVEHandler{}
			got, err := h.verifySearchInternalFlag(c)

			if tt.wantErr {
				if err == nil {
					t.Errorf("%s: expected error, got nil", tt.name)
				}
			} else {
				if err != nil {
					t.Errorf("%s: expected no error, got %v", tt.name, err)
				}
				if got.Keyword != tt.wantKeyword {
					t.Errorf("%s: expected keyword %q, got %q", tt.name, tt.wantKeyword, got.Keyword)
				}
			}
		})
	}
}

func TestVerifyInternalFlagCVEs_TableDriven(t *testing.T) {
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}
	tests := []struct {
		name        string
		jsonRequest string
		wantErr     bool
		errContains string
		wantFlags   []string
		wantIDs     int
	}{
		{
			name:        "invalid/missing action cause validate fail",
			jsonRequest: `{"flags_name":["a"],"ids":["id"],"filter":{}}`,
			wantErr:     true,
			errContains: "action",
		},
		{
			name:        "invalid body, action is string (should fail validate)",
			jsonRequest: `{"action":"lala","flags_name":["a"],"ids":["id"],"filter":{}}`, // action sai type
			wantErr:     true,
			errContains: "action",
		},
		{
			name:        "filter verify fail: size negative",
			jsonRequest: `{"action":1,"flags_name":["abc"],"ids":["id"],"filter":{"size":-1}}`,
			wantErr:     true,
			errContains: "size",
		},
		{
			name:        "exceed max IDs (should fail)",
			jsonRequest: `{"action":1,"flags_name":["xx"],"ids":[` + strings.Repeat(`"a",`, 1001) + `"a"],"filter":{}}`,
			wantErr:     true,
			errContains: "IDs list cannot contain more than 1000",
		},
		{
			name:        "empty flags (should fail)",
			jsonRequest: `{"action":1,"flags_name":[],"ids":["id"],"filter":{}}`,
			wantErr:     true,
			errContains: "Flag list must contain at least one flag",
		},
		{
			name:        "invalid action",
			jsonRequest: `{"action":4,"flags_name":["abc"],"ids":["id"],"filter":{}}`,
			wantErr:     true,
			errContains: "action must be 1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.jsonRequest))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			h := &CVEHandler{}
			got, err := h.verifyInternalFlagCVEs(c)

			t.Logf("GOT: %+v", got)
			if err != nil {
				t.Logf("ERR: %v", err)
			}

			if tc.wantErr {
				if err == nil {
					t.Fatalf("Expected error but got nil")
				}
				// lenient check
				if tc.errContains != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.errContains)) {
					t.Errorf("Error should contain %q, got %v", tc.errContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if len(tc.wantFlags) != 0 {
					if !reflect.DeepEqual(got.FlagsName, tc.wantFlags) {
						t.Errorf("Expected flags: %+v, got %+v", tc.wantFlags, got.FlagsName)
					}
				}
				if tc.wantIDs != 0 && len(got.IDs) != tc.wantIDs {
					t.Errorf("Expected %d IDs, got %d", tc.wantIDs, len(got.IDs))
				}
			}
		})
	}
}

func TestCVEHandler_Config(t *testing.T) {
	t.Run("Success - returns config", func(t *testing.T) {
		// Setup
		handler := &CVEHandler{}
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/config", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Execute
		err := handler.Config(c)

		// Debug output
		t.Logf("Error: %v", err)
		t.Logf("Status Code: %d", rec.Code)
		t.Logf("Response Body: %s", rec.Body.String())
		t.Logf("Response Headers: %v", rec.Header())

		// Minimal assertions
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	})
}

func TestCVEHandler_Identify(t *testing.T) {
	// Setup
	handler := &CVEHandler{}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/identify", nil)
	req.Host = "localhost"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Mock user_name
	c.Set("user_name", "testuser")

	// Execute
	err := handler.Identify(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "testuser")
}

func TestProcessCVEIDs(t *testing.T) {
	testCases := []struct {
		name           string
		inputIDs       []string
		expectedResult []string
		expectedError  bool
	}{
		{
			name:     "Valid CVE IDs",
			inputIDs: []string{"CVE-2023-1234", "cve-2022-5678"},
			expectedResult: []string{
				hash.SHA1("CVE-2023-1234"),
				hash.SHA1("CVE-2022-5678"),
			},
			expectedError: false,
		},
		{
			name:     "Mixed case and format",
			inputIDs: []string{"CVE-2023-1234", "CVE-2022-5678", "OTHER-ID"},
			expectedResult: []string{
				hash.SHA1("CVE-2023-1234"),
				hash.SHA1("CVE-2022-5678"),
			},
			expectedError: false,
		},
		{
			name:           "No valid CVE IDs",
			inputIDs:       []string{"RANDOM-ID", "ANOTHER-ID"},
			expectedResult: nil,
			expectedError:  true,
		},
		{
			name:           "Empty input",
			inputIDs:       []string{},
			expectedResult: nil,
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ProcessCVEIDs(tc.inputIDs)

			if tc.expectedError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

func TestFetchCVEs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCVERepo := mocks.NewMockCVERepository(ctrl)
	mockEnrichment := mocks.NewMockEnrichmentRepository(ctrl)
	mockElastic := mocks.NewMockGlobalRepository(ctrl)

	mockEnrichment.EXPECT().
		CVE().
		Return(mockCVERepo).
		AnyTimes()
	mockElastic.EXPECT().
		Enrichment().
		Return(mockEnrichment).
		AnyTimes()

	type fields struct {
		elastic *mocks.MockGlobalRepository
	}
	type args struct {
		body *model.RequestCVECommon
	}

	tests := []struct {
		name      string
		setupMock func()
		args      args
		wantIDs   []string
		wantErr   bool
	}{
		{
			name: "Truyền IDs, expect trả về 1 CVE",
			setupMock: func() {
				mockCVERepo.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVE{{ID: "abc"}}, nil).
					Times(1)
			},
			args: args{
				body: &model.RequestCVECommon{
					IDs: []string{"abc"},
					Filter: model.RequestCVESearch{
						Status: []int{2},
					},
				},
			},
			wantIDs: []string{"abc"},
			wantErr: false,
		},
		{
			name:      "Filter.Approved.Lte > 0, Status != 2 -> trả empty slice, không gọi Find",
			setupMock: func() {},
			args: args{
				body: &model.RequestCVECommon{
					Filter: model.RequestCVESearch{
						Time: model.CVESearchTime{
							Approved: model.RangeInt64{Gte: 0, Lte: 10},
						},
						Status: []int{1},
					},
				},
			},
			wantIDs: []string{},
			wantErr: false,
		},
		{
			name: "Không có IDs, không bị lọc, expect Find trả về 1 CVE",
			setupMock: func() {
				mockCVERepo.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVE{{ID: "xyz"}}, nil).
					Times(1)
			},
			args: args{
				body: &model.RequestCVECommon{
					IDs: nil,
					Filter: model.RequestCVESearch{
						Status: []int{2},
					},
				},
			},
			wantIDs: []string{"xyz"},
			wantErr: false,
		},
		{
			name: "Handle lỗi Find trả về lỗi",
			setupMock: func() {
				mockCVERepo.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New("find error!")).
					Times(1)
			},
			args: args{
				body: &model.RequestCVECommon{
					IDs: []string{"123"},
					Filter: model.RequestCVESearch{
						Status: []int{2},
					},
				},
			},
			wantIDs: nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl.Finish()
			ctrl = gomock.NewController(t)
			mockCVERepo = mocks.NewMockCVERepository(ctrl)
			mockEnrichment = mocks.NewMockEnrichmentRepository(ctrl)
			mockElastic = mocks.NewMockGlobalRepository(ctrl)

			mockEnrichment.EXPECT().CVE().Return(mockCVERepo).AnyTimes()
			mockElastic.EXPECT().Enrichment().Return(mockEnrichment).AnyTimes()

			if tt.setupMock != nil {
				tt.setupMock()
			}

			handler := &CVEHandler{elastic: mockElastic}
			got, err := handler.FetchCVEs(tt.args.body)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				var gotIDs []string
				for _, cve := range got {
					gotIDs = append(gotIDs, cve.ID)
				}
				require.ElementsMatch(t, tt.wantIDs, gotIDs)
			}
		})
	}
}

func TestVerifyStatistic(t *testing.T) {
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}
	handler := &CVEHandler{}

	tests := []struct {
		name     string
		bodyJSON string
		wantErr  bool
		want     model.RequestCVEStatistic
	}{
		{
			name:     "valid: lowercase checker, trim flags",
			bodyJSON: `{"checker":"TeSTabc", "internal_flags":[" f1  "," ","f2 ",""]}`,
			wantErr:  false,
			want: model.RequestCVEStatistic{
				Checker:       "testabc",
				InternalFlags: []string{"f1", "f2"},
			},
		},
		{
			name:     "valid: empty checker, all-space flags",
			bodyJSON: `{"checker":"", "internal_flags":[" ",""]}`,
			wantErr:  false,
			want: model.RequestCVEStatistic{
				Checker:       "",
				InternalFlags: []string{},
			},
		},
		{
			name:     "valid: checker viết thường, flags nhiều nội dung",
			bodyJSON: `{"checker":"allok", "internal_flags":["  x ","yy","z "]}`,
			wantErr:  false,
			want: model.RequestCVEStatistic{
				Checker:       "allok",
				InternalFlags: []string{"x", "yy", "z"},
			},
		},
		{
			name:     "invalid json, báo lỗi",
			bodyJSON: `{invalid}`,
			wantErr:  true,
			want:     model.RequestCVEStatistic{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(tc.bodyJSON)))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			got, err := handler.verifyStatistic(c)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			if got.InternalFlags == nil {
				got.InternalFlags = []string{}
			}
			if tc.want.InternalFlags == nil {
				tc.want.InternalFlags = []string{}
			}
			require.Equal(t, tc.want.Checker, got.Checker)

			require.Equal(t, len(tc.want.InternalFlags), len(got.InternalFlags),
				"Số lượng flags không khớp, got=%#v, want=%#v", got.InternalFlags, tc.want.InternalFlags)
			for i := range tc.want.InternalFlags {
				require.Equal(t, tc.want.InternalFlags[i], got.InternalFlags[i],
					"Flags khác tại vị trí %d, got=%#v, want=%#v", i, got.InternalFlags, tc.want.InternalFlags)
			}
		})
	}
}

func TestCVEHandler_ValidateCVE(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(mockCVERepo *mocks.MockCVERepository)
		body      *model.RequestCVESearch
		wantCode  int
		wantData  interface{}
		wantErr   bool
	}{
		//{
		//	name: "Find returns non-empty results",
		//	setupMock: func(mockCVERepo *mocks.MockCVERepository) {
		//		mockCVERepo.EXPECT().
		//			Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		//			Return([]*model.CVE{
		//				{
		//					ID: "cve1",
		//				},
		//			}, nil).
		//			Times(1)
		//	},
		//	body:     &model.RequestCVESearch{},
		//	wantCode: rest.StatusOK,
		//	wantData: map[string]interface{}{
		//		"detail": map[string]interface{}{
		//			"data": []interface{}{
		//				map[string]interface{}{
		//					"id": "cve1",
		//				},
		//			},
		//		},
		//		"message": "OK",
		//		"success": true,
		//	},
		//	wantErr: false,
		//},
		{
			name: "Find returns empty results",
			setupMock: func(mockCVERepo *mocks.MockCVERepository) {
				mockCVERepo.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVE{}, nil).
					Times(1)
			},
			body:     &model.RequestCVESearch{},
			wantCode: rest.StatusOK,
			wantData: map[string]interface{}{
				"detail": map[string]interface{}{
					"data": nil,
				},
				"message": "OK",
				"success": true,
			},
			wantErr: false,
		},
		{
			name: "Find returns internal error",
			setupMock: func(mockCVERepo *mocks.MockCVERepository) {
				mockCVERepo.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New("internal error")).
					Times(1)
			},
			body:     &model.RequestCVESearch{},
			wantCode: rest.StatusInternalServerError,
			wantData: nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockCVERepo := mocks.NewMockCVERepository(ctrl)
			mockEnrichment := mocks.NewMockEnrichmentRepository(ctrl)
			mockElastic := mocks.NewMockGlobalRepository(ctrl)

			mockEnrichment.EXPECT().
				CVE().
				Return(mockCVERepo).
				AnyTimes()

			mockElastic.EXPECT().
				Enrichment().
				Return(mockEnrichment).
				AnyTimes()

			tt.setupMock(mockCVERepo)

			handler := &CVEHandler{
				elastic: mockElastic,
			}

			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}
			var req *http.Request
			if tt.body != nil {
				jsonBody, err := json.Marshal(tt.body)
				require.NoError(t, err)
				req = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(jsonBody))
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			} else {
				req = httptest.NewRequest(http.MethodPost, "/", nil)
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			err := handler.ValidateCVE(c)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantCode, rec.Code)

			if tt.wantData != nil {
				resp := make(map[string]interface{})
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				require.NoError(t, err)
				require.Equal(t, tt.wantData, resp)
			}
		})
	}
}

func TestCVEHandler_SearchInternalFlag(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(mockCVEInternalRepo *mocks.MockCVEInternalFlagRepository)
		body        *model.RequestInternalFlagSearch
		rawBody     []byte
		wantCode    int
		wantTotal   int64
		wantLen     int
		wantFirstID string
		wantErr     bool
	}{
		{
			name: "Find returns non-empty results",
			setupMock: func(mockCVEInternalRepo *mocks.MockCVEInternalFlagRepository) {
				mockCVEInternalRepo.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVEInternalFlag{{ID: "if1"}}, int64(1), nil).
					Times(1)
			},
			body:        &model.RequestInternalFlagSearch{},
			wantCode:    http.StatusOK,
			wantTotal:   1,
			wantLen:     1,
			wantFirstID: "if1",
			wantErr:     false,
		},
		{
			name: "Find returns empty results",
			setupMock: func(mockCVEInternalRepo *mocks.MockCVEInternalFlagRepository) {
				mockCVEInternalRepo.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVEInternalFlag{}, int64(0), nil).
					Times(1)
			},
			body:      &model.RequestInternalFlagSearch{},
			wantCode:  http.StatusOK,
			wantTotal: 0,
			wantLen:   0,
			wantErr:   false,
		},
		{
			name: "Find returns internal error",
			setupMock: func(mockCVEInternalRepo *mocks.MockCVEInternalFlagRepository) {
				mockCVEInternalRepo.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, int64(0), errors.New("internal error")).
					Times(1)
			},
			body:     &model.RequestInternalFlagSearch{},
			wantCode: http.StatusInternalServerError,
			wantErr:  false,
		},

		// BadRequest cases
		{
			name:      "BadRequest - malformed_JSON",
			setupMock: nil, // handler phải trả 400 trước khi gọi repo
			rawBody:   []byte(`{"foo": }`),
			wantCode:  http.StatusBadRequest,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockCVEInternalRepo := mocks.NewMockCVEInternalFlagRepository(ctrl)
			mockEnrichment := mocks.NewMockEnrichmentRepository(ctrl)
			mockElastic := mocks.NewMockGlobalRepository(ctrl)

			mockEnrichment.EXPECT().
				CVEInternalFlag().
				Return(mockCVEInternalRepo).
				AnyTimes()

			mockElastic.EXPECT().
				Enrichment().
				Return(mockEnrichment).
				AnyTimes()

			// Nếu testcase không định nghĩa setupMock (ví dụ BadRequest), assert Find không được gọi
			if tt.setupMock != nil {
				tt.setupMock(mockCVEInternalRepo)
			} else {
				mockCVEInternalRepo.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Times(0)
			}

			handler := &CVEHandler{
				elastic: mockElastic,
			}

			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}

			var req *http.Request
			if tt.rawBody != nil {
				req = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(tt.rawBody))
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			} else if tt.body != nil {
				jsonBody, err := json.Marshal(tt.body)
				require.NoError(t, err)
				req = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(jsonBody))
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			} else {
				req = httptest.NewRequest(http.MethodPost, "/", nil)
			}

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := handler.SearchInternalFlag(c)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			t.Logf("status=%d body=%s", rec.Code, rec.Body.String())

			require.Equal(t, tt.wantCode, rec.Code)

			// kiểm tra body cho các status tương ứng
			if tt.wantCode == http.StatusOK {
				var resp map[string]interface{}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), "unmarshal response")

				// detail object
				detailIntf, ok := resp["detail"]
				require.True(t, ok, "response missing 'detail'")
				detail, ok := detailIntf.(map[string]interface{})
				require.True(t, ok, "'detail' is not object")

				// total
				totalVal, ok := detail["total"]
				require.True(t, ok, "response detail missing total")
				require.Equal(t, float64(tt.wantTotal), totalVal)

				// data
				dataIntf, hasData := detail["data"]
				if tt.wantLen == 0 {
					if hasData && dataIntf != nil {
						dataSlice, ok := dataIntf.([]interface{})
						require.True(t, ok, "detail.data is not array")
						require.Equal(t, 0, len(dataSlice))
					}
				} else {
					require.True(t, hasData, "response detail missing data")
					dataSlice, ok := dataIntf.([]interface{})
					require.True(t, ok, "detail.data is not array")
					require.Equal(t, tt.wantLen, len(dataSlice))

					first, ok := dataSlice[0].(map[string]interface{})
					require.True(t, ok, "first element is not object")
					if tt.wantFirstID != "" {
						require.Equal(t, tt.wantFirstID, first["id"])
					}
				}
			}

			if tt.wantCode == http.StatusInternalServerError {
				var resp map[string]interface{}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

				detailIntf, ok := resp["detail"]
				require.True(t, ok, "response missing detail")
				detail, ok := detailIntf.(map[string]interface{})
				require.True(t, ok, "detail is not object")

				errVal, ok := detail["error"].(string)
				require.True(t, ok, "detail.error missing or not a string")
				require.Contains(t, errVal, "internal error")
			}

			if tt.wantCode == http.StatusBadRequest {
				var resp map[string]interface{}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

				// ưu tiên detail.error nếu có
				if detailIntf, ok := resp["detail"]; ok {
					detail, ok := detailIntf.(map[string]interface{})
					require.True(t, ok, "detail is not object")
					errVal, ok := detail["error"].(string)
					require.True(t, ok, "detail.error missing or not string")
					require.NotEmpty(t, errVal)
				} else if topErr, ok := resp["error"].(string); ok {
					require.NotEmpty(t, topErr)
				} else {
					t.Fatalf("BadRequest response missing error field: %s", rec.Body.String())
				}
			}
		})
	}
}

func TestCVEHandler_CVEsInternalFlag_TableDriven(t *testing.T) {
	tests := []struct {
		name              string
		rawBody           []byte
		setupMock         func(mInt *mocks.MockCVEInternalFlagRepository, mCVE *mocks.MockCVERepository, mHist *mocks.MockHistoryRepository)
		wantCode          int
		wantDetailContain string
	}{
		{
			name:    "Success Mark-> 200",
			rawBody: []byte(`{"ids":["CVE-2025-7939"],"action":1,"flags_name":["flag-a"]}`),
			setupMock: func(mInt *mocks.MockCVEInternalFlagRepository, mCVE *mocks.MockCVERepository, mHist *mocks.MockHistoryRepository) {
				mInt.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVEInternalFlag{}, int64(0), nil).
					AnyTimes()
				mInt.EXPECT().StoreAll(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				sample := &model.CVE{ID: "CVE-2025-7939", InternalFlag: []string{}}
				mCVE.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVE{sample}, nil).
					AnyTimes()

				mCVE.EXPECT().Store(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				mHist.EXPECT().Store(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			},
			wantCode:          http.StatusOK,
			wantDetailContain: "CVE-2025-7939",
		},
		{
			name:    "Success Delete-> 200",
			rawBody: []byte(`{"ids":["CVE-2025-7939"],"action":2,"flags_name":["flag-a"]}`),
			setupMock: func(mInt *mocks.MockCVEInternalFlagRepository, mCVE *mocks.MockCVERepository, mHist *mocks.MockHistoryRepository) {
				mInt.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVEInternalFlag{}, int64(0), nil).
					AnyTimes()
				mInt.EXPECT().StoreAll(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				sample := &model.CVE{ID: "CVE-2025-7939", InternalFlag: []string{}}
				mCVE.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVE{sample}, nil).
					AnyTimes()

				mCVE.EXPECT().Store(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				mHist.EXPECT().Store(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			},
			wantCode:          http.StatusOK,
			wantDetailContain: "CVE-2025-7939",
		},
		{
			name:    "BadRequest flags_name empty -> 400 (allow CVEInternalFlag.Find)",
			rawBody: []byte(`{"ids":["CVE-2025-7931"],"action":1,"flags_name":[]}`),
			setupMock: func(mInt *mocks.MockCVEInternalFlagRepository, mCVE *mocks.MockCVERepository, mHist *mocks.MockHistoryRepository) {
				mInt.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVEInternalFlag{}, int64(0), nil).
					AnyTimes()
			},
			wantCode:          http.StatusBadRequest,
			wantDetailContain: "flag list must contain at least one flag",
		},
		{
			name:    "CVE repo returns empty -> 400",
			rawBody: []byte(`{"ids":["CVE-2025-9999"]}`),
			setupMock: func(mInt *mocks.MockCVEInternalFlagRepository, mCVE *mocks.MockCVERepository, mHist *mocks.MockHistoryRepository) {
				mInt.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVEInternalFlag{}, int64(0), nil).
					AnyTimes()

				mCVE.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVE{}, nil).
					AnyTimes()
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name:    "CVE repo Find internal error -> 500 (ensure internal-flag Find expected too)",
			rawBody: []byte(`{"ids":["CVE-2025-7939"],"action":3,"flags_name":["flag-a"]}`),
			setupMock: func(mInt *mocks.MockCVEInternalFlagRepository, mCVE *mocks.MockCVERepository, mHist *mocks.MockHistoryRepository) {
				mInt.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVEInternalFlag{}, int64(0), nil).
					AnyTimes()

				mCVE.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New("es internal error")).
					AnyTimes()
			},
			wantCode:          http.StatusBadRequest,
			wantDetailContain: "es internal error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockInt := mocks.NewMockCVEInternalFlagRepository(ctrl)
			mockCVE := mocks.NewMockCVERepository(ctrl)
			mockHist := mocks.NewMockHistoryRepository(ctrl)
			mockEnr := mocks.NewMockEnrichmentRepository(ctrl)
			mockG := mocks.NewMockGlobalRepository(ctrl)

			mockEnr.EXPECT().CVEInternalFlag().Return(mockInt).AnyTimes()
			mockEnr.EXPECT().CVE().Return(mockCVE).AnyTimes()
			mockEnr.EXPECT().CVEHistory().Return(mockHist).AnyTimes()
			mockG.EXPECT().Enrichment().Return(mockEnr).AnyTimes()

			if tt.setupMock != nil {
				tt.setupMock(mockInt, mockCVE, mockHist)
			} else {
				mockInt.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				mockCVE.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			}

			handler := &CVEHandler{elastic: mockG}
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(tt.rawBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", "unittest")

			err := handler.CVEsInternalFlag(c)
			require.NoError(t, err)
			require.Equal(t, tt.wantCode, rec.Code)
			t.Logf("resp body: %s", rec.Body.String())
		})
	}
}

func TestCVEHandler_CVELifeCycleV2_TableDriven(t *testing.T) {
	tests := []struct {
		name              string
		queryParams       map[string]string
		setupMock         func(mCVELifecycle *mocks.MockCVELifeCycleV2Repository)
		wantCode          int
		wantDetailContain string
		wantResponse      map[string]interface{}
	}{
		{
			name: "Success Full Data",
			queryParams: map[string]string{
				"offset": "0",
				"size":   "10",
				"sort":   "-created",
			},
			setupMock: func(mCVELifecycle *mocks.MockCVELifeCycleV2Repository) {
				mockResults := []*model.CVELifeCycleV2{
					{
						ID: "CVE-2025-1234",
					},
				}
				mCVELifecycle.EXPECT().
					Find(
						gomock.Any(),
						gomock.Any(),
						gomock.Eq([]string{"-created"}),
						gomock.Any(),
						gomock.Any(),
					).
					Return(mockResults, int64(1), nil).
					AnyTimes()
			},
			wantCode:          http.StatusOK,
			wantDetailContain: "CVE-2025-1234",
		},
		{
			name: "Unknown_Error_Scenario",
			setupMock: func(mockRepo *mocks.MockCVELifeCycleV2Repository) {
				mockRepo.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, int64(0), errors.New("some unknown error"))
			},
			wantCode: http.StatusInternalServerError,
			wantResponse: map[string]interface{}{
				"success": false,
				"message": "Internal Server Error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockElastic := mocks.NewMockGlobalRepository(ctrl)
			mockEnrichment := mocks.NewMockEnrichmentRepository(ctrl)
			mockCVELifecycle := mocks.NewMockCVELifeCycleV2Repository(ctrl)

			mockElastic.EXPECT().Enrichment().Return(mockEnrichment).AnyTimes()
			mockEnrichment.EXPECT().CVELifeCycleV2().Return(mockCVELifecycle).AnyTimes()

			if tt.setupMock != nil {
				tt.setupMock(mockCVELifecycle)
			}

			handler := &CVEHandler{elastic: mockElastic}

			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}
			req := httptest.NewRequest(http.MethodGet, "/lifecycle", nil)

			q := req.URL.Query()
			for k, v := range tt.queryParams {
				q.Add(k, v)
			}
			req.URL.RawQuery = q.Encode()

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_name", "unittest")

			err := handler.CVELifeCycleV2(c)
			require.NoError(t, err)

			require.Equal(t, tt.wantCode, rec.Code)

			t.Logf("resp body: %s", rec.Body.String())

			if tt.wantDetailContain != "" {
				assert.Contains(t, rec.Body.String(), tt.wantDetailContain)
			}
		})
	}
}

func TestCVEHandler_EPSSHistory_TableDriven(t *testing.T) {
	tests := []struct {
		name              string
		idParam           string
		queryParams       map[string]string
		setupMock         func(mEPSS *mocks.MockCVEEPSSHistoryRepository)
		wantCode          int
		wantDetailContain string
		wantResponse      map[string]interface{}
	}{
		{
			name:    "Success Full Data",
			idParam: "CVE-2025-1234",
			queryParams: map[string]string{
				"offset": "0",
				"size":   "10",
			},
			setupMock: func(mEPSS *mocks.MockCVEEPSSHistoryRepository) {
				mockResults := []*model.CVEEPSSHistory{
					{
						ID: "CVE-2025-1234",
					},
				}
				// Dùng gomock.Any() cho các arg để tránh so sánh nil slice gây panic
				mEPSS.EXPECT().
					Find(
						gomock.Any(), // ctx
						gomock.Any(), // query
						gomock.Any(), // sort (was []string{"-date"})
						gomock.Any(), // offset
						gomock.Any(), // size
					).
					Return(mockResults, int64(1), nil).
					AnyTimes()
			},
			wantCode:          http.StatusOK,
			wantDetailContain: "CVE-2025-1234",
		},
		{
			name:    "NotFound_Returns_Empty_List",
			idParam: "CVE-2025-9999",
			queryParams: map[string]string{
				"offset": "0",
				"size":   "10",
			},
			setupMock: func(mEPSS *mocks.MockCVEEPSSHistoryRepository) {
				// Nếu handler so sánh err.Error() == es.NotFoundError,
				// hãy trả về error có message tương ứng. Nếu es.NotFoundError là "", kiểm tra giá trị đó.
				mEPSS.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.CVEEPSSHistory{}, int64(0), errors.New(es.NotFoundError))
			},
			wantCode:          http.StatusOK,
			wantDetailContain: `"data":[]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Mock repositories (chỉnh tên constructors nếu khác)
			mockElastic := mocks.NewMockGlobalRepository(ctrl)
			mockEnrichment := mocks.NewMockEnrichmentRepository(ctrl)
			mockEPSS := mocks.NewMockCVEEPSSHistoryRepository(ctrl)

			// Wire mocks
			mockElastic.EXPECT().Enrichment().Return(mockEnrichment).AnyTimes()
			mockEnrichment.EXPECT().CVEEPSSHistory().Return(mockEPSS).AnyTimes()

			// Setup test-specific mocks
			if tt.setupMock != nil {
				tt.setupMock(mockEPSS)
			}

			// Create handler with mocked dependencies
			handler := &CVEHandler{elastic: mockElastic}

			// Create Echo context for GET
			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}
			req := httptest.NewRequest(http.MethodGet, "/:id/epss_history", nil)

			// Add query parameters
			q := req.URL.Query()
			for k, v := range tt.queryParams {
				q.Add(k, v)
			}
			req.URL.RawQuery = q.Encode()

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// IMPORTANT: set id param from path
			c.SetParamNames("id")
			c.SetParamValues(tt.idParam)

			// set user if handler needs it
			c.Set("user_name", "unittest")

			// Call handler
			err := handler.EPSSHistory(c)
			require.NoError(t, err)
			// Nếu mong về 200 thì require no error, ngược lại chỉ kiểm tra status code
			if tt.wantCode == http.StatusOK {
				require.NoError(t, err)
			}
			// Check response code
			require.Equal(t, tt.wantCode, rec.Code)

			// Log response body for debugging
			t.Logf("resp body: %s", rec.Body.String())

			// Optional: Additional assertions based on response content
			if tt.wantDetailContain != "" {
				assert.Contains(t, rec.Body.String(), tt.wantDetailContain)
			}
			if tt.wantResponse != nil {
				// Parse top-level presence / basic checks
				for k, v := range tt.wantResponse {
					assert.Contains(t, rec.Body.String(), k)
					_ = v
				}
			}
		})
	}
}

func TestCVEHandler_CVEHistory_TableDriven(t *testing.T) {
	tests := []struct {
		name              string
		idParam           string
		queryParams       map[string]string
		setupMock         func(mHistory *mocks.MockHistoryRepository)
		wantCode          int
		wantDetailContain string
		wantResponseKeys  []string
	}{
		{
			name:    "Success_Full_Data",
			idParam: "CVE-2025-1234",
			queryParams: map[string]string{
				"offset": "0",
				"size":   "10",
			},
			setupMock: func(mHistory *mocks.MockHistoryRepository) {
				mockHistories := []*model.History{
					{
						ID:          "CVE-2025-1234",
						Created:     1620000000,
						Document:    "doc-1",
						Editor:      "editor-1",
						Action:      "update",
						Description: "desc",
						HistoryType: "cve",
					},
				}
				mHistory.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(mockHistories, int64(1), nil).
					AnyTimes()
			},
			wantCode:          http.StatusOK,
			wantDetailContain: "CVE-2025-1234",
			wantResponseKeys:  []string{"data", "total"},
		},
		{
			name:    "VerifyHistory_BadRequest",
			idParam: "CVE-2025-1234",
			queryParams: map[string]string{
				"size": "-1",
			},
			setupMock: func(mHistory *mocks.MockHistoryRepository) {
				mHistory.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.History{}, int64(0), nil).
					AnyTimes()
			},
			wantCode:          http.StatusBadRequest,
			wantDetailContain: "error",
		},
		{
			name:    "Repo_NotFound_Returns_EmptyList",
			idParam: "CVE-2025-9999",
			queryParams: map[string]string{
				"offset": "0",
				"size":   "10",
			},
			setupMock: func(mHistory *mocks.MockHistoryRepository) {
				mHistory.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.History{}, int64(0), errors.New(es.NotFoundError)).
					AnyTimes()
			},
			wantCode:          http.StatusOK,
			wantDetailContain: `"data":[]`,
		},
		{
			name:    "Repo_OtherError_Returns_500",
			idParam: "CVE-2025-5000",
			queryParams: map[string]string{
				"offset": "0",
				"size":   "10",
			},
			setupMock: func(mHistory *mocks.MockHistoryRepository) {
				mHistory.EXPECT().
					Find(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.History{}, int64(0), errors.New("db failure")).
					AnyTimes()
			},
			wantCode: http.StatusInternalServerError,
			wantResponseKeys: []string{
				"success",
				"message",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockGlobal := mocks.NewMockGlobalRepository(ctrl)
			mockEnrichment := mocks.NewMockEnrichmentRepository(ctrl)
			mockHistory := mocks.NewMockHistoryRepository(ctrl)

			mockGlobal.EXPECT().Enrichment().Return(mockEnrichment).AnyTimes()
			mockEnrichment.EXPECT().CVEHistory().Return(mockHistory).AnyTimes()

			if tt.setupMock != nil {
				tt.setupMock(mockHistory)
			}

			handler := &CVEHandler{elastic: mockGlobal}

			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}
			req := httptest.NewRequest(http.MethodGet, "/:id/history", nil)

			q := req.URL.Query()
			for k, v := range tt.queryParams {
				q.Add(k, v)
			}
			req.URL.RawQuery = q.Encode()

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// set path param id
			c.SetParamNames("id")
			c.SetParamValues(tt.idParam)

			// nếu handler dùng user_name trong context
			c.Set("user_name", "unittest")

			err := handler.CVEHistory(c)

			// chỉ require no error cho case expect 200 (success or NotFound-as-empty)
			if tt.wantCode == http.StatusOK {
				require.NoError(t, err)
			}

			require.Equal(t, tt.wantCode, rec.Code)
			t.Logf("resp body: %s", rec.Body.String())

			if tt.wantDetailContain != "" {
				assert.Contains(t, rec.Body.String(), tt.wantDetailContain)
			}
			for _, k := range tt.wantResponseKeys {
				assert.Contains(t, rec.Body.String(), k)
			}
		})
	}
}

func TestCVEHandler_Statistic_TableDriven(t *testing.T) {
	tests := []struct {
		name              string
		rawBody           []byte
		setupMock         func(mCVE *mocks.MockCVERepository, mEnr *mocks.MockEnrichmentRepository, mG *mocks.MockGlobalRepository)
		wantCode          int
		wantDetailContain string
	}{
		{
			name:    "Success with empty filters -> 200",
			rawBody: []byte(`{"checker":"","internal_flags":[]}`),
			setupMock: func(mCVE *mocks.MockCVERepository, mEnr *mocks.MockEnrichmentRepository, mG *mocks.MockGlobalRepository) {
				mockAggResult := map[string][]es.ResultAggregationCount{
					"score.cvss_v2.severity": {{Value: "HIGH", Count: 10}},
					"score.cvss_v3.severity": {{Value: "HIGH", Count: 15}},
					"score.cvss_v4.severity": {{Value: "HIGH", Count: 5}},
					"score.cna.severity":     {{Value: "HIGH", Count: 8}},
					"status":                 {{Value: "ACTIVE", Count: 100}},
					"checker":                {{Value: "checker1", Count: 30}},
					"score.global.version":   {{Value: "3.0", Count: 40}},
					"score.global.severity":  {{Value: "HIGH", Count: 50}},
					"score.vti.severity":     {{Value: "HIGH", Count: 45}},
					"source":                 {{Value: "others", Count: 60}},
					"languages":              {{Value: "vi", Count: 80}},
				}

				mCVE.EXPECT().AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(mockAggResult, nil).AnyTimes()
				mCVE.EXPECT().AggregationCountWithSize(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(map[string][]es.ResultAggregationCount{"internal_flag": {{Value: "flag1", Count: 25}}}, nil).Times(1)
				mCVE.EXPECT().Count(gomock.Any(), gomock.Any()).Return(int64(15), nil).Times(1)

				mEnr.EXPECT().CVE().Return(mCVE).AnyTimes()
				mG.EXPECT().Enrichment().Return(mEnr).AnyTimes()
			},
			wantCode: http.StatusOK,
		},
		{
			name:    "Success with internal flags filter -> 200",
			rawBody: []byte(`{"checker":"","internal_flags":["flag1","flag2"]}`),
			setupMock: func(mCVE *mocks.MockCVERepository, mEnr *mocks.MockEnrichmentRepository, mG *mocks.MockGlobalRepository) {
				mockAggResult := map[string][]es.ResultAggregationCount{
					"score.cvss_v2.severity": {{Value: "HIGH", Count: 10}},
					"score.cvss_v3.severity": {{Value: "HIGH", Count: 15}},
					"score.cvss_v4.severity": {{Value: "HIGH", Count: 5}},
					"score.cna.severity":     {{Value: "HIGH", Count: 8}},
					"status":                 {{Value: "ACTIVE", Count: 100}},
					"checker":                {{Value: "checker1", Count: 30}},
					"score.global.version":   {{Value: "3.0", Count: 40}},
					"score.global.severity":  {{Value: "HIGH", Count: 50}},
					"score.vti.severity":     {{Value: "HIGH", Count: 45}},
					"source":                 {{Value: "others", Count: 60}},
					"languages":              {{Value: "vi", Count: 80}},
				}

				mCVE.EXPECT().AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(mockAggResult, nil).AnyTimes()
				mCVE.EXPECT().AggregationCountWithSize(gomock.Any(), gomock.Any(), map[string]int{"internal_flag": 10000}).
					Return(map[string][]es.ResultAggregationCount{
						"internal_flag": {
							{Value: "flag1", Count: 20},
							{Value: "flag2", Count: 15},
						},
					}, nil).Times(1)
				mCVE.EXPECT().Count(gomock.Any(), gomock.Any()).Return(int64(15), nil).Times(1)

				mEnr.EXPECT().CVE().Return(mCVE).AnyTimes()
				mG.EXPECT().Enrichment().Return(mEnr).AnyTimes()
			},
			wantCode: http.StatusOK,
		},
		{
			name:    "Success with checker filter -> 200",
			rawBody: []byte(`{"checker":"test-checker","internal_flags":[]}`),
			setupMock: func(mCVE *mocks.MockCVERepository, mEnr *mocks.MockEnrichmentRepository, mG *mocks.MockGlobalRepository) {
				mockAggResult := map[string][]es.ResultAggregationCount{
					"score.cvss_v2.severity": {{Value: "HIGH", Count: 5}},
					"score.cvss_v3.severity": {{Value: "HIGH", Count: 8}},
					"score.cvss_v4.severity": {{Value: "HIGH", Count: 3}},
					"score.cna.severity":     {{Value: "HIGH", Count: 4}},
					"status":                 {{Value: "ACTIVE", Count: 50}},
					"checker":                {{Value: "test-checker", Count: 30}},
					"score.global.version":   {{Value: "3.0", Count: 20}},
					"score.global.severity":  {{Value: "HIGH", Count: 25}},
					"score.vti.severity":     {{Value: "HIGH", Count: 20}},
					"source":                 {{Value: "others", Count: 30}},
					"languages":              {{Value: "vi", Count: 40}},
				}

				mCVE.EXPECT().AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(mockAggResult, nil).AnyTimes()
				mCVE.EXPECT().AggregationCountWithSize(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(map[string][]es.ResultAggregationCount{"internal_flag": {{Value: "flag1", Count: 10}}}, nil).Times(1)
				mCVE.EXPECT().Count(gomock.Any(), gomock.Any()).Return(int64(5), nil).Times(1)

				mEnr.EXPECT().CVE().Return(mCVE).AnyTimes()
				mG.EXPECT().Enrichment().Return(mEnr).AnyTimes()
			},
			wantCode:          http.StatusOK,
			wantDetailContain: "test-checker",
		},
		{
			name:    "Success with source transformation -> 200",
			rawBody: []byte(`{"checker":"","internal_flags":[]}`),
			setupMock: func(mCVE *mocks.MockCVERepository, mEnr *mocks.MockEnrichmentRepository, mG *mocks.MockGlobalRepository) {
				mockAggResult := map[string][]es.ResultAggregationCount{
					"source": {
						{Value: "others", Count: 50},
						{Value: "nvd", Count: 30},
					},
					"score.cvss_v2.severity": {{Value: "HIGH", Count: 10}},
					"score.cvss_v3.severity": {{Value: "HIGH", Count: 15}},
					"score.cvss_v4.severity": {{Value: "HIGH", Count: 5}},
					"score.cna.severity":     {{Value: "HIGH", Count: 8}},
					"status":                 {{Value: "ACTIVE", Count: 100}},
					"checker":                {{Value: "checker1", Count: 30}},
					"score.global.version":   {{Value: "3.0", Count: 40}},
					"score.global.severity":  {{Value: "HIGH", Count: 50}},
					"score.vti.severity":     {{Value: "HIGH", Count: 45}},
					"languages":              {{Value: "vi", Count: 80}},
				}

				mCVE.EXPECT().AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(mockAggResult, nil).AnyTimes()
				mCVE.EXPECT().AggregationCountWithSize(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(map[string][]es.ResultAggregationCount{"internal_flag": {{Value: "flag1", Count: 25}}}, nil).Times(1)
				mCVE.EXPECT().Count(gomock.Any(), gomock.Any()).Return(int64(15), nil).Times(1)

				mEnr.EXPECT().CVE().Return(mCVE).AnyTimes()
				mG.EXPECT().Enrichment().Return(mEnr).AnyTimes()
			},
			wantCode: http.StatusOK,
		},
		{
			name:    "CVE AggregationCount V2 error -> 500",
			rawBody: []byte(`{"checker":"","internal_flags":[]}`),
			setupMock: func(mCVE *mocks.MockCVERepository, mEnr *mocks.MockEnrichmentRepository, mG *mocks.MockGlobalRepository) {
				mCVE.EXPECT().AggregationCount(gomock.Any(), gomock.Any(), []string{"score.cvss_v2.severity"}).
					Return(nil, errors.New("elasticsearch connection error")).Times(1)

				mEnr.EXPECT().CVE().Return(mCVE).AnyTimes()
				mG.EXPECT().Enrichment().Return(mEnr).AnyTimes()
			},
			wantCode:          http.StatusInternalServerError,
			wantDetailContain: "Internal Server Error",
		},
		{
			name:    "Success with CVSS version counting -> 200",
			rawBody: []byte(`{"checker":"","internal_flags":[]}`),
			setupMock: func(mCVE *mocks.MockCVERepository, mEnr *mocks.MockEnrichmentRepository, mG *mocks.MockGlobalRepository) {
				mockAggResult := map[string][]es.ResultAggregationCount{
					"score.global.version": {
						{Value: defs.VersionCvssV20, Count: 10}, // case defs.VersionCvssV20: continue
						{Value: defs.VersionCvssV30, Count: 15}, // case defs.VersionCvssV30, defs.VersionCvssV31: continue
						{Value: defs.VersionCvssV31, Count: 8},  // case defs.VersionCvssV30, defs.VersionCvssV31: continue
						{Value: defs.VersionCvssV40, Count: 5},  // case defs.VersionCvssV40: continue
						{Value: "unknown_version", Count: 12},   // default: totalUnknown += item.Count
					},
					// Thêm các mock result khác để đảm bảo test case thành công
					"score.cvss_v2.severity": {{Value: "HIGH", Count: 10}},
					"score.cvss_v3.severity": {{Value: "HIGH", Count: 15}},
					"score.cvss_v4.severity": {{Value: "HIGH", Count: 5}},
					"score.cna.severity":     {{Value: "HIGH", Count: 8}},
					"status":                 {{Value: "ACTIVE", Count: 100}},
					"checker":                {{Value: "checker1", Count: 30}},
					"score.global.severity":  {{Value: "HIGH", Count: 50}},
					"score.vti.severity":     {{Value: "HIGH", Count: 45}},
					"source":                 {{Value: "others", Count: 60}},
					"languages":              {{Value: "vi", Count: 80}},
				}

				mCVE.EXPECT().AggregationCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(mockAggResult, nil).AnyTimes()
				mCVE.EXPECT().AggregationCountWithSize(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(map[string][]es.ResultAggregationCount{"internal_flag": {{Value: "flag1", Count: 25}}}, nil).Times(1)
				mCVE.EXPECT().Count(gomock.Any(), gomock.Any()).Return(int64(15), nil).Times(1)

				mEnr.EXPECT().CVE().Return(mCVE).AnyTimes()
				mG.EXPECT().Enrichment().Return(mEnr).AnyTimes()
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockCVE := mocks.NewMockCVERepository(ctrl)
			mockEnr := mocks.NewMockEnrichmentRepository(ctrl)
			mockG := mocks.NewMockGlobalRepository(ctrl)

			if tt.setupMock != nil {
				tt.setupMock(mockCVE, mockEnr, mockG)
			}

			handler := &CVEHandler{
				elastic: mockG,
			}

			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}
			req := httptest.NewRequest(http.MethodPost, "/statistic", bytes.NewReader(tt.rawBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := handler.Statistic(c)
			require.NoError(t, err)
			require.Equal(t, tt.wantCode, rec.Code)

			if tt.wantDetailContain != "" {
				require.Contains(t, rec.Body.String(), tt.wantDetailContain)
			}

			t.Logf("resp body: %s", rec.Body.String())
		})
	}
}

func TestCVEHandler_VerifyRejectCVEs(t *testing.T) {
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}

	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "valid request",
			body:    `{"ids":["CVE-2023-12345"],"filter":{"status":[1]},"reason":"Test"}`,
			wantErr: false,
		},
		{
			name:    "invalid ids type",
			body:    `{"ids":123,"filter":{"status":[1]},"reason":"Test"}`,
			wantErr: true,
		},
		{
			name:    "empty ids",
			body:    `{"ids":[],"filter":{"status":[2]},"reason":"Test"}`,
			wantErr: true,
		},
		{
			name:    "invalid filter",
			body:    `{"ids":["CVE-2023-12345"],"filter":{"status":["valid"]},"reason":"Test"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			h := &CVEHandler{}
			_, err := h.verifyRejectCVEs(c)

			if tt.wantErr {
				if err == nil {
					t.Errorf("%s: expected error, got nil", tt.name)
				}
			} else {
				if err != nil {
					t.Errorf("%s: expected no error, got %v", tt.name, err)
				}
			}
		})
	}
}

func TestCVEHandler_VerifyConfirm(t *testing.T) {
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}

	tests := []struct {
		name           string
		body           string
		expectedStatus int
		wantErr        bool
	}{
		{
			name:           "reject status passes through",
			body:           fmt.Sprintf(`{"status":%d}`, defs.StatusCodeReject),
			expectedStatus: defs.StatusCodeReject,
			wantErr:        false,
		},
		{
			name:    "invalid status type",
			body:    `{"status":"invalid"}`,
			wantErr: true,
		},
		{
			name:    "empty status",
			body:    `{"status":0}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/confirm", strings.NewReader(tt.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			h := &CVEHandler{}
			body, err := h.verifyConfirm(c)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, body.Status)
			}
		})
	}
}

func TestCVEHandler_LifecycleCVE_Table(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(
			mockCVERepo *mocks.MockCVERepository,
			mockCVELifecycleRepo *mocks.MockCVELifeCycleV2Repository,
		)
		wantCode         int
		wantResponseBody map[string]interface{}
	}{
		{
			name: "Successful Create New CVE Lifecycle",
			setupMock: func(
				mockCVERepo *mocks.MockCVERepository,
				mockCVELifecycleRepo *mocks.MockCVELifeCycleV2Repository,
			) {
				// Mock find CVE
				mockCVERepo.EXPECT().
					Find(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).
					Return([]*model.CVE{
						{
							ID:   "cve-id-1",
							Name: "CVE-2023-1234",
						},
					}, nil)

				// Mock find bulk CVE Lifecycle - no existing records
				mockCVELifecycleRepo.EXPECT().
					FindBulk(gomock.Any(), []string{"CVE-2023-1234"}).
					Return([]*model.CVELifeCycleV2{}, nil)

				// Mock store bulk CVE Lifecycle
				mockCVELifecycleRepo.EXPECT().
					StoreBulk(gomock.Any(), gomock.Any()).
					Return(nil)
			},
			wantCode: http.StatusOK,
			wantResponseBody: map[string]interface{}{
				"detail": map[string]interface{}{
					"message": true,
				},
				"message": "OK",
				"success": true,
			},
		},
		{
			name: "Error - FindBulk CVE Lifecycle Failed",
			setupMock: func(
				mockCVERepo *mocks.MockCVERepository,
				mockCVELifecycleRepo *mocks.MockCVELifeCycleV2Repository,
			) {
				mockCVERepo.EXPECT().
					Find(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).
					Return([]*model.CVE{
						{
							ID:   "cve-id-1",
							Name: "CVE-2023-1234",
						},
					}, nil)

				mockCVELifecycleRepo.EXPECT().
					FindBulk(gomock.Any(), []string{"CVE-2023-1234"}).
					Return(nil, errors.New("database connection failed"))
			},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockElastic := mocks.NewMockGlobalRepository(ctrl)
			mockEnrichment := mocks.NewMockEnrichmentRepository(ctrl)
			mockCVERepo := mocks.NewMockCVERepository(ctrl)
			mockCVELifecycleRepo := mocks.NewMockCVELifeCycleV2Repository(ctrl)

			mockElastic.EXPECT().Enrichment().Return(mockEnrichment).AnyTimes()
			mockEnrichment.EXPECT().CVE().Return(mockCVERepo).AnyTimes()
			mockEnrichment.EXPECT().CVELifeCycleV2().Return(mockCVELifecycleRepo).AnyTimes()

			handler := &CVEHandler{
				elastic: mockElastic,
			}

			e := echo.New()
			e.Validator = &CustomValidator{validator: validator.New()}
			req := httptest.NewRequest(http.MethodPost, "/lifecycle-cve", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			tt.setupMock(mockCVERepo, mockCVELifecycleRepo)

			err := handler.LifecycleCVE(c)

			require.NoError(t, err)

			assert.Equal(t, tt.wantCode, rec.Code)

			if tt.wantResponseBody != nil {
				var response map[string]interface{}
				err := json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, tt.wantResponseBody, response)
			}
		})
	}
}
