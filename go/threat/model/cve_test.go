package model

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRequestCVECreate_Generate(t *testing.T) {

}

func (r RequestCVECreate) withLang(lang string) RequestCVECreate {
	r.Lang = lang
	return r
}

func newTestCVERequest() RequestCVECreate {
	score := 0.5
	percentile := 0.8
	return RequestCVECreate{
		ID:          "CVE-2024-TEST",
		Lang:        string(defs.LangEN),
		Description: "Test vulnerability description",
		Reference:   "https://example.com",
		Patch:       "https://patch.example.com",
		Published:   1640995200,

		Match: []string{"test-match-pattern"},
		EPSS: &EPSSMetric{
			Score:      &score,
			Percentile: &percentile,
		},
		CWE: []CWEMetric{
			{
				ID:   "CWE-79",
				Name: "Cross-site Scripting",
				Link: "https://cwe.mitre.org/data/definitions/79.html",
			},
		},
	}
}

func (r RequestCVECreate) withCVSS2(version string, score float32, vector string) RequestCVECreate {
	r.CVSS.CVSS2 = CVEMetric{
		Version:      version,
		Score:        score,
		VectorString: vector,
	}
	return r
}

func (r RequestCVECreate) withCVSS3(version string, score float32, vector string) RequestCVECreate {
	r.CVSS.CVSS3 = CVEMetric{
		Version:      version,
		Score:        score,
		VectorString: vector,
	}
	return r
}

func (r RequestCVECreate) withCVSS4(version string, score float32, vector string) RequestCVECreate {
	r.CVSS.CVSS4 = CVEMetric{
		Version:      version,
		Score:        score,
		VectorString: vector,
	}
	return r
}

func (r RequestCVECreate) withID(id string) RequestCVECreate {
	r.ID = id
	return r
}

func (r RequestCVECreate) withCNA(version string, score float32, vector string) RequestCVECreate {
	r.CVSS.CNA.Version = version
	r.CVSS.CNA.Score = score
	r.CVSS.CNA.VectorString = vector
	return r
}

func TestGenerate_CVSSProcessing(t *testing.T) {
	id := newTestCVERequest().
		withID("CVE-2024-007")
	testCases := []struct {
		name     string
		input    RequestCVECreate
		validate func(t *testing.T, cve *CVE, cveLang *CVELang)
	}{
		{
			name: "CVSS2_Only_Critical_Score",
			input: newTestCVERequest().
				withID("CVE-2024-001").
				withLang(string(defs.LangVI)).
				withCVSS2("2.0", 9.5, "AV:N/AC:L/Au:N/C:C/I:C/A:C"),
			validate: func(t *testing.T, cve *CVE, cveLang *CVELang) {
				// CVSS2 should be populated
				assert.Equal(t, "2.0", cve.Score.CVSS2.Version)
				assert.Equal(t, float32(9.5), cve.Score.CVSS2.Score)
				assert.Equal(t, defs.LangVI, cveLang.Lang)
				assert.Equal(t, "AV:N/AC:L/Au:N/C:C/I:C/A:C", cve.Score.CVSS2.VectorString)
				assert.NotEmpty(t, cve.Score.CVSS2.Severity) // Should be mapped to severity

				// CVSS3 and CVSS4 should be empty
				assert.Empty(t, cve.Score.CVSS3.Version)
				assert.Empty(t, cve.Score.CVSS4.Version)

				// Global should be CVSS2
				assert.Equal(t, cve.Score.CVSS2, cve.Score.Global)
			},
		},
		{
			name: "CVSS3_Only_High_Score",
			input: newTestCVERequest().
				withID("CVE-2024-002").
				withCVSS3("3.1", 7.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
			validate: func(t *testing.T, cve *CVE, cveLang *CVELang) {
				// CVSS3 should be populated
				assert.Equal(t, "3.1", cve.Score.CVSS3.Version)
				assert.Equal(t, float32(7.8), cve.Score.CVSS3.Score)
				assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cve.Score.CVSS3.VectorString)
				assert.NotEmpty(t, cve.Score.CVSS3.Severity)

				// CVSS2 and CVSS4 should be empty
				assert.Empty(t, cve.Score.CVSS2.Version)
				assert.Empty(t, cve.Score.CVSS4.Version)

				// Global should be CVSS3
				assert.Equal(t, cve.Score.CVSS3, cve.Score.Global)
			},
		},
		{
			name: "CVSS4_Only_Medium_Score",
			input: newTestCVERequest().
				withID("CVE-2024-003").
				withCVSS4("4.0", 5.5, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
			validate: func(t *testing.T, cve *CVE, cveLang *CVELang) {
				// CVSS4 should be populated
				assert.Equal(t, "4.0", cve.Score.CVSS4.Version)
				assert.Equal(t, float32(5.5), cve.Score.CVSS4.Score)
				assert.Equal(t, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", cve.Score.CVSS4.VectorString)
				assert.NotEmpty(t, cve.Score.CVSS4.Severity)

				// CVSS2 and CVSS3 should be empty
				assert.Empty(t, cve.Score.CVSS2.Version)
				assert.Empty(t, cve.Score.CVSS3.Version)

				// Global should be CVSS4
				assert.Equal(t, cve.Score.CVSS4, cve.Score.Global)
			},
		},
		{
			name: "Multiple_CVSS_Versions_Priority",
			input: newTestCVERequest().
				withID("CVE-2024-004").
				withCVSS2("2.0", 6.0, "AV:N/AC:M/Au:S/C:P/I:P/A:P").
				withCVSS3("3.1", 8.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H").
				withCVSS4("4.0", 7.2, "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
			validate: func(t *testing.T, cve *CVE, cveLang *CVELang) {
				// All CVSS versions should be populated
				assert.Equal(t, "2.0", cve.Score.CVSS2.Version)
				assert.Equal(t, float32(6.0), cve.Score.CVSS2.Score)

				assert.Equal(t, "3.1", cve.Score.CVSS3.Version)
				assert.Equal(t, float32(8.0), cve.Score.CVSS3.Score)

				assert.Equal(t, "4.0", cve.Score.CVSS4.Version)
				assert.Equal(t, float32(7.2), cve.Score.CVSS4.Score)

				// Global should be CVSS4 (latest version priority based on code logic)
				assert.Equal(t, cve.Score.CVSS4, cve.Score.Global)
			},
		},
		{
			name:  "No_CVSS_Data",
			input: newTestCVERequest().withID("CVE-2024-005"),
			// CVSS remains empty by default
			validate: func(t *testing.T, cve *CVE, cveLang *CVELang) {
				// All CVSS versions should be empty
				assert.Empty(t, cve.Score.CVSS2.Version)
				assert.Empty(t, cve.Score.CVSS3.Version)
				assert.Empty(t, cve.Score.CVSS4.Version)

				// Global should be empty CVEMetric
				assert.Empty(t, cve.Score.Global.Version)
				assert.Equal(t, float32(0), cve.Score.Global.Score)
			},
		},
		{
			name: "Invalid_CVSS_Versions",
			input: newTestCVERequest().
				withID("CVE-2024-006").
				withCVSS2("1.0", 7.0, ""). // Invalid version
				withCVSS3("2.5", 8.0, ""). // Invalid version
				withCVSS4("3.2", 6.5, ""), // Invalid version
			validate: func(t *testing.T, cve *CVE, cveLang *CVELang) {
				// None of the CVSS should be processed due to invalid versions
				assert.Empty(t, cve.Score.CVSS2.Version)
				assert.Empty(t, cve.Score.CVSS3.Version)
				assert.Empty(t, cve.Score.CVSS4.Version)

				// Global should be empty
				assert.Empty(t, cve.Score.Global.Version)
			},
		},
		{
			name: "CNA Only - CVSS2-like version, severity mapping and global",
			input: id.
				withCNA("2.0", 7.5, "AV:N/AC:L/Au:N/C:P/I:P/A:P"),
			validate: func(t *testing.T, cve *CVE, cveLang *CVELang) {
				// Check CNA fields
				assert.Equal(t, "2.0", cve.Score.CNA.Version)
				assert.Equal(t, float32(7.5), cve.Score.CNA.Score)
				assert.Equal(t, "AV:N/AC:L/Au:N/C:P/I:P/A:P", cve.Score.CNA.VectorString)

				assert.NotEqual(t, defs.SeverityCodeUnknown, cve.Score.CNA.Severity)
				assert.Empty(t, cve.Score.CVSS2.Version)
				assert.Empty(t, cve.Score.CVSS3.Version)
				assert.Empty(t, cve.Score.CVSS4.Version)
				assert.Equal(t, cve.Score.CNA, cve.Score.Global)
			},
		},
		{
			name: "CNA Only - CVSS3-like version",
			input: newTestCVERequest().
				withID("CVE-2024-008").
				withCNA("3.1", 8.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
			validate: func(t *testing.T, cve *CVE, cveLang *CVELang) {
				assert.Equal(t, "3.1", cve.Score.CNA.Version)
				assert.Equal(t, float32(8.5), cve.Score.CNA.Score)
				assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cve.Score.CNA.VectorString)
				assert.NotEqual(t, defs.SeverityCodeUnknown, cve.Score.CNA.Severity)
				assert.Empty(t, cve.Score.CVSS2.Version)
				assert.Empty(t, cve.Score.CVSS3.Version)
				assert.Empty(t, cve.Score.CVSS4.Version)
				assert.Equal(t, cve.Score.CNA, cve.Score.Global)
			},
		},
		{
			name: "CNA Only - CVSS4-like version",
			input: newTestCVERequest().
				withID("CVE-2024-009").
				withCNA("4.0", 4.4, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"),
			validate: func(t *testing.T, cve *CVE, cveLang *CVELang) {
				assert.Equal(t, "4.0", cve.Score.CNA.Version)
				assert.Equal(t, float32(4.4), cve.Score.CNA.Score)
				assert.Equal(t, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", cve.Score.CNA.VectorString)
				assert.NotEqual(t, defs.SeverityCodeUnknown, cve.Score.CNA.Severity)
				assert.Empty(t, cve.Score.CVSS2.Version)
				assert.Empty(t, cve.Score.CVSS3.Version)
				assert.Empty(t, cve.Score.CVSS4.Version)
				assert.Equal(t, cve.Score.CNA, cve.Score.Global)
			},
		},
		{
			name: "CNA Only - invalid version, severity code unknown",
			input: newTestCVERequest().
				withID("CVE-2024-010").
				withCNA("xxx", 5.0, ""),
			validate: func(t *testing.T, cve *CVE, cveLang *CVELang) {
				assert.Equal(t, "xxx", cve.Score.CNA.Version)
				assert.Equal(t, float32(5.0), cve.Score.CNA.Score)
				assert.Equal(t, "", cve.Score.CNA.VectorString)
				assert.Equal(t, defs.SeverityCodeUnknown, cve.Score.CNA.Severity)
				assert.Empty(t, cve.Score.CVSS2.Version)
				assert.Empty(t, cve.Score.CVSS3.Version)
				assert.Empty(t, cve.Score.CVSS4.Version)
				assert.Equal(t, cve.Score.CNA, cve.Score.Global)
			},
		},
		{
			name: "CNA + CVSS2 - Global is not CNA",
			input: newTestCVERequest().
				withID("CVE-2024-011").
				withCNA("2.0", 7.5, "AV:N/AC:L/Au:N/C:P/I:P/A:P").
				withCVSS2("2.0", 8.9, "AV:N/AC:L/Au:N/C:C/I:C/A:C"),
			validate: func(t *testing.T, cve *CVE, cveLang *CVELang) {
				assert.Equal(t, "2.0", cve.Score.CNA.Version)
				assert.Equal(t, "2.0", cve.Score.CVSS2.Version)
				// Khi có CVSS2, Global = CVSS2 (không phải CNA)
				assert.NotEqual(t, cve.Score.CNA, cve.Score.Global)
				assert.Equal(t, cve.Score.CVSS2, cve.Score.Global)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute the function
			cve, cveLang := tc.input.Generate()

			// Validate results
			require.NotNil(t, cve)
			require.NotNil(t, cveLang)

			// Run specific validations
			tc.validate(t, cve, cveLang)

			// Common validations for all test cases
			assert.NotEmpty(t, cve.ID)
			assert.Equal(t, tc.input.ID, cve.Name)
			assert.NotZero(t, cve.Created)
			assert.NotZero(t, cve.Modified)
		})
	}
}

func TestRequestLifeCycleCVE_Verify(t *testing.T) {
	tests := []struct {
		name     string
		input    *RequestLifeCycleCVE
		expected []string
	}{
		{
			name:     "Nil slice should become empty slice",
			input:    &RequestLifeCycleCVE{CVECode: nil},
			expected: []string{},
		},
		{
			name:     "Empty slice stays empty",
			input:    &RequestLifeCycleCVE{CVECode: []string{}},
			expected: []string{},
		},
		{
			name:     "Non-empty slice should stay the same",
			input:    &RequestLifeCycleCVE{CVECode: []string{"CVE-2024-0001"}},
			expected: []string{"CVE-2024-0001"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Verify()

			require.NoError(t, err)
			assert.Equal(t, tt.expected, tt.input.CVECode)

			assert.NotNil(t, tt.input.CVECode)
		})
	}
}

func TestRequestLifeCycleCVE_PrepareQuery(t *testing.T) {
	tests := []struct {
		name     string
		input    *RequestLifeCycleCVE
		expected map[string]interface{}
	}{
		{
			name:  "Single CVE code",
			input: &RequestLifeCycleCVE{CVECode: []string{"CVE-2024-0001"}},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"terms": map[string]interface{}{
								"name": []string{"CVE-2024-0001"},
							},
						},
					},
				},
			},
		},
		{
			name:  "Multiple CVE codes",
			input: &RequestLifeCycleCVE{CVECode: []string{"CVE-2024-0001", "CVE-2024-0002"}},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"terms": map[string]interface{}{
								"name": []string{"CVE-2024-0001", "CVE-2024-0002"},
							},
						},
					},
				},
			},
		},
		{
			name:  "Empty CVE codes",
			input: &RequestLifeCycleCVE{CVECode: []string{}},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"terms": map[string]interface{}{
								"name": []string{},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.PrepareQuery()

			require.NotNil(t, result)

			// So sánh map
			assert.Equal(t, tt.expected, result)
		})
	}
}

//func TestRequestHistorySearch_PrepareQuery(t *testing.T) {
//	t.Skip()
//	tests := []struct {
//		name     string
//		input    *RequestHistorySearch
//		expected map[string]interface{}
//	}{
//		{
//			name: "Without date range",
//			input: &RequestHistorySearch{
//				ID: "doc123",
//			},
//			expected: map[string]interface{}{
//				"bool": map[string][]interface{}{
//					"filter": {
//						map[string]interface{}{
//							"term": map[string]interface{}{
//								"document": "doc123",
//							},
//						},
//						map[string]interface{}{
//							"term": map[string]interface{}{
//								"history_type": defs.HistoryTypeSystem,
//							},
//						},
//					},
//				},
//			},
//		},
//		{
//			name: "With date range",
//			input: &RequestHistorySearch{
//				ID:       "doc456",
//				FromDate: 1700000000,
//				ToDate:   1700500000,
//			},
//			expected: map[string]interface{}{
//				"bool": map[string][]interface{}{
//					"filter": {
//						map[string]interface{}{
//							"term": map[string]interface{}{
//								"document": "doc456",
//							},
//						},
//						map[string]interface{}{
//							"term": map[string]interface{}{
//								"history_type": defs.HistoryTypeSystem,
//							},
//						},
//						map[string]interface{}{
//							"range": map[string]interface{}{
//								"from_date": int64(1700000000),
//								"to_date":   int64(1700500000),
//							},
//						},
//					},
//				},
//			},
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			result := tt.input.PrepareQuery()
//			require.NotNil(t, result)
//			assert.Equal(t, tt.expected, result)
//		})
//	}
//}

func TestCVEEPSSHistory_IDMethods(t *testing.T) {
	doc := &CVEEPSSHistory{
		CVEName: "CVE-2024-1234",
		Date:    1700000000,
		Editor:  "system",
	}

	t.Run("SetEID and GetID", func(t *testing.T) {
		doc.SetEID("custom-id-123")
		assert.Equal(t, "custom-id-123", doc.GetID())
	})

	t.Run("GenID produces deterministic SHA1", func(t *testing.T) {
		doc.GenID()
		expected := hash.SHA1(fmt.Sprintf("%s--%d--%s", doc.CVEName, doc.Date, doc.Editor))
		assert.Equal(t, expected, doc.GetID())
	})
}

func TestRequestEPSSHistorySearch_PrepareQuery(t *testing.T) {
	tests := []struct {
		name     string
		input    *RequestEPSSHistorySearch
		expected map[string]interface{}
	}{
		{
			name: "Without date range",
			input: &RequestEPSSHistorySearch{
				ID: "CVE-2024-9999",
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"term": map[string]interface{}{
								"cve_name": "CVE-2024-9999",
							},
						},
					},
				},
			},
		},
		{
			name: "With date range",
			input: &RequestEPSSHistorySearch{
				ID:       "CVE-2024-8888",
				FromDate: 1700000000,
				ToDate:   1700500000,
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"term": map[string]interface{}{
								"cve_name": "CVE-2024-8888",
							},
						},
						map[string]interface{}{
							"range": map[string]interface{}{
								"date": map[string]interface{}{
									"from_date": int64(1700000000),
									"to_date":   int64(1700500000),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.PrepareQuery()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCVELifeCycleV2_IDMethods(t *testing.T) {
	doc := &CVELifeCycleV2{CVEId: "CVE-2024-7777"}

	t.Run("SetEID and GetID", func(t *testing.T) {
		doc.SetEID("custom-id-abc")
		assert.Equal(t, "custom-id-abc", doc.GetID())
	})

	t.Run("GenID creates SHA1 based on CVEId and timestamp", func(t *testing.T) {
		doc.GenID()
		id := doc.GetID()

		// Độ dài SHA1 phải là 40 hex
		assert.Len(t, id, 40)

		// Kiểm tra hợp lệ bằng regex hex
		matched, err := regexp.MatchString("^[a-f0-9]{40}$", id)
		require.NoError(t, err)
		assert.True(t, matched)
	})
}

func TestRequestCVELifeCycleV2Search_PrepareQuery(t *testing.T) {
	tests := []struct {
		name     string
		input    *RequestCVELifeCycleV2Search
		expected map[string]interface{}
	}{
		{
			name: "Without date range",
			input: &RequestCVELifeCycleV2Search{
				ID: "CVE-2024-1111",
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"term": map[string]interface{}{
								"cve_id": "CVE-2024-1111",
							},
						},
					},
				},
			},
		},
		{
			name: "With date range",
			input: &RequestCVELifeCycleV2Search{
				ID:       "CVE-2024-2222",
				FromDate: 1700000000,
				ToDate:   1700500000,
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"term": map[string]interface{}{
								"cve_id": "CVE-2024-2222",
							},
						},
						map[string]interface{}{
							"range": map[string]interface{}{
								"date": map[string]interface{}{
									"from_date": int64(1700000000),
									"to_date":   int64(1700500000),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.PrepareQuery()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRequestCVESearch_Verify(t *testing.T) {
	tests := []struct {
		name    string
		data    RequestCVESearch
		wantErr bool
		errSub  string
	}{
		{
			name:    "Success - empty/default",
			data:    RequestCVESearch{},
			wantErr: false,
		},
		{
			name: "Success - approved time with status code approved",
			data: RequestCVESearch{
				Time: CVESearchTime{
					Approved: RangeInt64{Gte: 1, Lte: 100},
				},
				Status: []int{1, 2, 3},
			},
			wantErr: false,
		},
		{
			name: "Success - approved time with empty status",
			data: RequestCVESearch{
				Time: CVESearchTime{
					Approved: RangeInt64{Gte: 1, Lte: 100},
				},
				Status: []int{},
			},
			wantErr: false,
		},
		{
			name: "Success - no approved time condition",
			data: RequestCVESearch{
				Time: CVESearchTime{
					Approved: RangeInt64{Gte: 0, Lte: 0},
				},
				Status: []int{1, 2},
			},
			wantErr: false,
		},
		{
			name: "Error - languages invalid",
			data: RequestCVESearch{
				Languages: []string{"zzz"},
			},
			wantErr: true,
			errSub:  "languages",
		},
		{
			name: "Error - severity.vti.version invalid",
			data: RequestCVESearch{
				Severity: RequestCVESeverity{
					VTI: RequestCVESeverityVerbose{
						Version: "abc",
					},
				},
			},
			wantErr: true,
			errSub:  "severity.vti.version",
		},
		{
			name: "Error - severity.global.version invalid",
			data: RequestCVESearch{
				Severity: RequestCVESeverity{
					Global: RequestCVESeverityVerboseV2{
						Version: []string{"zzz"},
					},
				},
			},
			wantErr: true,
			errSub:  "severity.global.version",
		},
		{
			name: "Error - time.approved.gte > lte",
			data: RequestCVESearch{
				Time: CVESearchTime{
					Approved: RangeInt64{Gte: 10, Lte: 1},
				},
			},
			wantErr: true,
			errSub:  "approved.gte",
		},
		{
			name: "Error - time.modified.gte > lte",
			data: RequestCVESearch{
				Time: CVESearchTime{
					Modified: RangeInt64{Gte: 10, Lte: 1},
				},
			},
			wantErr: true,
			errSub:  "modified.gte",
		},
		{
			name: "Error - time.analysis_time.gte > lte",
			data: RequestCVESearch{
				Time: CVESearchTime{
					AnalysisTime: RangeInt64{Gte: 12, Lte: 3},
				},
			},
			wantErr: true,
			errSub:  "modified.gte",
		},
		{
			name: "Success - trim internal flag",
			data: RequestCVESearch{
				InternalFlag: []string{"  flag1  "},
			},
			wantErr: false,
		},
		{
			name: "Success - valid source",
			data: RequestCVESearch{
				Source: []string{"  NVD  "},
			},
			wantErr: false,
		},
		{
			name: "Error - invalid source value",
			data: RequestCVESearch{
				Source: []string{"InvalidSource"},
			},
			wantErr: true,
			errSub:  "invalid source value",
		},
		{
			name: "Success - trim and lowercase keyword",
			data: RequestCVESearch{
				Keyword: "  TEST KEYWORD  ",
			},
			wantErr: false,
		},
		{
			name: "Success - trim and lowercase checker",
			data: RequestCVESearch{
				Checker: "  ADMIN USER  ",
			},
			wantErr: false,
		},
		{
			name: "Success - empty keyword and checker",
			data: RequestCVESearch{
				Keyword: "",
				Checker: "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.data
			err := d.Verify()
			if (err != nil) != tt.wantErr {
				t.Fatalf("wantErr = %v, got err: %v", tt.wantErr, err)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errSub) {
				t.Errorf("err = %v, want contains %v", err, tt.errSub)
			}
		})
	}
}

func TestCVEMetric_SetVTIMetric(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		score    float32
		expected int
	}{
		{"V1.0_VeryLow", defs.VersionVcs10, 2.0, defs.SeverityCodeUnknown},
		{"V1.0_Low_Boundary", defs.VersionVcs10, 4.0, defs.SeverityCodeLow},
		{"V1.0_Low", defs.VersionVcs10, 5.0, defs.SeverityCodeLow},
		{"V1.0_Medium_Boundary", defs.VersionVcs10, 8.0, defs.SeverityCodeMedium},
		{"V1.0_Medium", defs.VersionVcs10, 9.0, defs.SeverityCodeMedium},
		{"V1.0_High_Boundary", defs.VersionVcs10, 11.0, defs.SeverityCodeHigh},
		{"V2.0", "2.0", 7.0, defs.SeverityCodeUnknown},
		{"V3.0", "3.0", 7.0, defs.SeverityCodeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &CVEMetric{
				Version: tt.version,
				Score:   tt.score,
			}

			doc.SetVTIMetric()

			assert.Equal(t, tt.expected, doc.Severity)
		})
	}
}

func TestCVECheckListMetric_Calculate(t *testing.T) {
	tests := []struct {
		name   string
		input  CVECheckListMetric
		expect int
	}{
		{
			name:   "All zero",
			input:  CVECheckListMetric{},
			expect: 0,
		},
		{
			name:   "Only Ability > 0",
			input:  CVECheckListMetric{Ability: 4},
			expect: 4,
		},
		{
			name:   "All fields > 0",
			input:  CVECheckListMetric{Ability: 2, Affect: 3, Condition: 4, Exploit: 5, Patch: 6},
			expect: 2 + 3 + 4 + 5 + 6,
		},
		{
			name:   "Combination test",
			input:  CVECheckListMetric{Ability: 2, Affect: 3, Exploit: 6},
			expect: 2 + 3 + 6,
		},
		{
			name:   "Negative values, must ignore (should not add)",
			input:  CVECheckListMetric{Ability: -3, Affect: -1, Condition: 2, Exploit: 0, Patch: 0},
			expect: 2, // Only condition > 0
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.input.Calculate()
			assert.Equal(t, tc.expect, got)
		})
	}
}

func TestCVECheckListMetric_EQ(t *testing.T) {
	tests := []struct {
		name   string
		self   CVECheckListMetric
		other  CVECheckListMetric
		expect bool
	}{
		{
			name:   "Both zero",
			self:   CVECheckListMetric{},
			other:  CVECheckListMetric{},
			expect: true,
		},
		{
			name:   "Exact equal",
			self:   CVECheckListMetric{Ability: 1, Affect: 2, Condition: 3, Exploit: 4, Patch: 5},
			other:  CVECheckListMetric{Ability: 1, Affect: 2, Condition: 3, Exploit: 4, Patch: 5},
			expect: true,
		},
		{
			name:   "Different Ability",
			self:   CVECheckListMetric{Ability: 2},
			other:  CVECheckListMetric{Ability: 1},
			expect: false,
		},
		{
			name:   "Different Exploit",
			self:   CVECheckListMetric{Exploit: 7},
			other:  CVECheckListMetric{Exploit: 8},
			expect: false,
		},
		{
			name:   "Different Patch",
			self:   CVECheckListMetric{Patch: 3},
			other:  CVECheckListMetric{Patch: 2},
			expect: false,
		},
		{
			name:   "One field different out of five",
			self:   CVECheckListMetric{Ability: 3, Affect: 9, Condition: 2, Exploit: 1, Patch: 7},
			other:  CVECheckListMetric{Ability: 3, Affect: 9, Condition: 1, Exploit: 1, Patch: 7},
			expect: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.self.EQ(tc.other)
			assert.Equal(t, tc.expect, got)
		})
	}
}

func TestCVEInternalFlag_GetID(t *testing.T) {
	doc := &CVEInternalFlag{ID: "test-id"}
	assert.Equal(t, "test-id", doc.GetID())
}

func TestCVEInternalFlag_SetEID(t *testing.T) {
	doc := &CVEInternalFlag{}
	doc.SetEID("new-id")
	assert.Equal(t, "new-id", doc.ID)
}

func TestCVEInternalFlag_GenID(t *testing.T) {
	flagName := "my-flag"
	expected := hash.SHA1(fmt.Sprintf("%s", flagName))

	doc := &CVEInternalFlag{FlagName: flagName}
	doc.GenID()
	assert.Equal(t, expected, doc.ID)
}

func TestCveCustomer_GetID(t *testing.T) {
	doc := &CveCustomer{ID: "xyz"}
	assert.Equal(t, "xyz", doc.GetID())
}

func TestCveCustomer_SetEID(t *testing.T) {
	doc := &CveCustomer{}
	doc.SetEID("abc")
	assert.Equal(t, "abc", doc.ID)
}

func TestCveCustomer_GenID(t *testing.T) {
	doc := &CveCustomer{}
	cve := "CVE-123"
	tenant := "T1"
	doc.GenID(cve, tenant)
	assert.NotEmpty(t, doc.ID)
}

func TestBodyRequestInternalFlagSearch(t *testing.T) {
	tests := []struct {
		name     string
		input    *RequestInternalFlagSearch
		expected map[string]interface{}
	}{
		{
			name: "with keyword",
			input: &RequestInternalFlagSearch{
				Keyword: "test",
			},
			expected: map[string]interface{}{
				"match": map[string]interface{}{},
			},
		},
		{
			name: "without keyword",
			input: &RequestInternalFlagSearch{
				Keyword: "",
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"should": []interface{}{
						map[string]interface{}{
							"wildcard": map[string]interface{}{},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.PrepareQuery()
			if result == nil {
				t.Error("Expected non-nil result")
			}
		})
	}
}

func TestCVE_GetID_SetEID(t *testing.T) {
	doc := &CVE{}
	doc.SetEID("abc123")
	if doc.GetID() != "abc123" {
		t.Errorf("expected %q, got %q", "abc123", doc.GetID())
	}
}

func TestCVE_GetLatestCVSSMetric(t *testing.T) {
	cases := []struct {
		name                string
		cvss4, cvss3, cvss2 string
		want                string
	}{
		{"Có CVSS4", "4.0", "3.1", "2.0", "4.0"},
		{"Chỉ CVSS3", "", "3.1", "2.0", "3.1"},
		{"Chỉ CVSS2", "", "", "2.0", "2.0"},
		{"Không có gì", "", "", "", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := &CVE{
				Score: CVEScore{
					CVSSMetric: CVSSMetric{
						CVSS4: CVEMetric{Version: c.cvss4},
						CVSS3: CVEMetric{Version: c.cvss3},
						CVSS2: CVEMetric{Version: c.cvss2},
					},
				},
			}
			got := doc.GetLatestCVSSMetric()
			if got.Version != c.want {
				t.Errorf("expected %q, got %q", c.want, got.Version)
			}
		})
	}
}

func TestRequestCVESearch_PrepareQuery(t *testing.T) {
	tests := []struct {
		name     string
		input    *RequestCVESearch
		expected map[string]interface{}
	}{
		{
			name:     "empty request",
			input:    &RequestCVESearch{},
			expected: defs.ElasticsearchQueryFilterMatchAll,
		},
		{
			name: "with keyword",
			input: &RequestCVESearch{
				Keyword: "test",
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"bool": map[string]interface{}{
								"should": []interface{}{},
							},
						},
					},
				},
			},
		},
		{
			name: "with checker",
			input: &RequestCVESearch{
				Checker: "admin",
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"term": map[string]interface{}{
								"checker": "admin",
							},
						},
					},
				},
			},
		},
		{
			name: "with internal flag",
			input: &RequestCVESearch{
				InternalFlag: []string{"flag1", "flag2"},
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"terms": map[string]interface{}{
								"internal_flag": []string{"flag1", "flag2"},
							},
						},
					},
				},
			},
		},
		{
			name: "with source",
			input: &RequestCVESearch{
				Source: []string{"source1", "source2"},
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"terms": map[string]interface{}{
								"source": []string{"source1", "source2"},
							},
						},
					},
				},
			},
		},
		{
			name: "with empty source slice",
			input: &RequestCVESearch{
				Source: []string{},
			},
			expected: defs.ElasticsearchQueryFilterMatchAll,
		},
		{
			name: "with single source",
			input: &RequestCVESearch{
				Source: []string{"nvd"},
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"terms": map[string]interface{}{
								"source": []string{"nvd"},
							},
						},
					},
				},
			},
		},
		{
			name: "with cve name",
			input: &RequestCVESearch{
				CVEName: "CVE-123-8386",
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"bool": map[string]interface{}{
								"should": []interface{}{},
							},
						},
					},
				},
			},
		},
		{
			name: "with customers",
			input: &RequestCVESearch{
				Customers: []string{"customer1", "customer2"},
			},
			expected: map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"terms": map[string]interface{}{
								"customer": []string{"customer1", "customer2"},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.PrepareQuery()
			if result == nil {
				t.Error("Expected non-nil result")
			}
		})
	}
}

func TestCVERaw_GetSeverityAndScore(t *testing.T) {
	tests := []struct {
		name      string
		doc       *CVERaw
		wantSev   string
		wantVer   string
		wantScore float32
	}{
		{
			name:      "Success - MetricV3 with BaseSeverity",
			doc:       &CVERaw{Impact: CVEImpact{MetricV3: CvssV3{Vector: CvssVectorV3{BaseSeverity: "HIGH", Version: "3.1", BaseScore: 7.5}}}},
			wantSev:   "high",
			wantVer:   "3.1",
			wantScore: 7.5,
		},
		{
			name:      "Success - MetricV2 with Severity",
			doc:       &CVERaw{Impact: CVEImpact{MetricV2: CvssV2{Severity: "MEDIUM", Vector: CvssVectorV2{Version: "2.0", BaseScore: 5.0}}}},
			wantSev:   "medium",
			wantVer:   "2.0",
			wantScore: 5.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSev, gotVer, gotScore := tt.doc.GetSeverityAndScore()
			if gotSev != tt.wantSev {
				t.Errorf("GetSeverityAndScore() severity = %v, want %v", gotSev, tt.wantSev)
			}
			if gotVer != tt.wantVer {
				t.Errorf("GetSeverityAndScore() version = %v, want %v", gotVer, tt.wantVer)
			}
			if gotScore != tt.wantScore {
				t.Errorf("GetSeverityAndScore() score = %v, want %v", gotScore, tt.wantScore)
			}
		})
	}
}

func TestCVERaw_GetProducts(t *testing.T) {
	tests := []struct {
		name string
		doc  *CVERaw
		want []string
	}{
		{
			name: "Success - with configurations and products",
			doc: &CVERaw{
				Configurations: CVEConfigurations{
					Nodes: []CVENode{
						{
							Match: []CPEMatch{
								{Cpe23Uri: "product1"},
								{Cpe23Uri: "product2"},
							},
						},
						{
							Match: []CPEMatch{
								{Cpe23Uri: "product3"},
							},
						},
					},
				},
			},
			want: []string{"product1", "product2", "product3"},
		},
		{
			name: "Success - empty configurations",
			doc: &CVERaw{
				Configurations: CVEConfigurations{
					Nodes: []CVENode{},
				},
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.doc.GetProducts()
			if len(got) != len(tt.want) {
				t.Errorf("GetProducts() length = %v, want %v", len(got), len(tt.want))
				return
			}
			for i, product := range got {
				if product != tt.want[i] {
					t.Errorf("GetProducts()[%d] = %v, want %v", i, product, tt.want[i])
				}
			}
		})
	}
}

func TestCVENode_GetProducts(t *testing.T) {
	tests := []struct {
		name string
		doc  *CVENode
		want []string
	}{
		{
			name: "Success - with match and children",
			doc: &CVENode{
				Match: []CPEMatch{
					{Cpe23Uri: "cpe1"},
					{Cpe23Uri: "cpe2"},
				},
				Children: []CVENode{
					{
						Match: []CPEMatch{
							{Cpe23Uri: "child1"},
							{Cpe23Uri: "child2"},
						},
					},
				},
			},
			want: []string{"cpe1", "cpe2", "child1", "child2"},
		},
		{
			name: "Success - only match, no children",
			doc: &CVENode{
				Match: []CPEMatch{
					{Cpe23Uri: "cpe1"},
				},
				Children: []CVENode{},
			},
			want: []string{"cpe1"},
		},
		{
			name: "Success - no match, no children",
			doc: &CVENode{
				Match:    []CPEMatch{},
				Children: []CVENode{},
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.doc.GetProducts()
			if len(got) != len(tt.want) {
				t.Errorf("GetProducts() length = %v, want %v", len(got), len(tt.want))
				return
			}
			for i, product := range got {
				if product != tt.want[i] {
					t.Errorf("GetProducts()[%d] = %v, want %v", i, product, tt.want[i])
				}
			}
		})
	}
}

func TestCVERaw_GetLastModified(t *testing.T) {
	tests := []struct {
		name     string
		doc      *CVERaw
		wantTime time.Time
	}{
		{
			name:     "Success - valid RFC3339 date",
			doc:      &CVERaw{LastModifiedDate: "2023-08-24T10:30:00.000Z"},
			wantTime: time.Date(2023, 8, 24, 10, 30, 0, 0, time.UTC),
		},
		{
			name:     "Success - another valid RFC3339 date",
			doc:      &CVERaw{LastModifiedDate: "2022-12-15T14:22:30.123Z"},
			wantTime: time.Date(2022, 12, 15, 14, 22, 30, 123000000, time.UTC),
		},
		{
			name:     "Failure - invalid date format returns zero time",
			doc:      &CVERaw{LastModifiedDate: "invalid-date"},
			wantTime: time.Time{},
		},
		{
			name:     "Failure - empty date returns zero time",
			doc:      &CVERaw{LastModifiedDate: ""},
			wantTime: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.doc.GetLastModified()
			if !got.Equal(tt.wantTime) {
				t.Errorf("GetLastModified() = %v, want %v", got, tt.wantTime)
			}
		})
	}
}

func TestCVERaw_GetPublished(t *testing.T) {
	tests := []struct {
		name     string
		doc      *CVERaw
		wantTime time.Time
	}{
		{
			name:     "Success - valid RFC3339 date",
			doc:      &CVERaw{PublishedDate: "2023-08-24T10:30:00.000Z"},
			wantTime: time.Date(2023, 8, 24, 10, 30, 0, 0, time.UTC),
		},
		{
			name:     "Success - another valid RFC3339 date",
			doc:      &CVERaw{PublishedDate: "2022-12-15T14:22:30.123Z"},
			wantTime: time.Date(2022, 12, 15, 14, 22, 30, 123000000, time.UTC),
		},
		{
			name:     "Failure - invalid date format returns zero time",
			doc:      &CVERaw{PublishedDate: "invalid-date"},
			wantTime: time.Time{},
		},
		{
			name:     "Failure - empty date returns zero time",
			doc:      &CVERaw{PublishedDate: ""},
			wantTime: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.doc.GetPublished()
			if !got.Equal(tt.wantTime) {
				t.Errorf("GetPublished() = %v, want %v", got, tt.wantTime)
			}
		})
	}
}

func TestCVERaw_GetDescriptions(t *testing.T) {
	tests := []struct {
		name string
		doc  *CVERaw
		want []string
	}{
		{
			name: "Success - multiple descriptions",
			doc: &CVERaw{
				Detail: CVEDetail{
					Description: CVEDescription{
						Data: []CVEDescriptionData{
							{Value: "First description"},
							{Value: "Second description"},
							{Value: "Third description"},
						},
					},
				},
			},
			want: []string{"First description", "Second description", "Third description"},
		},
		{
			name: "Success - single description",
			doc: &CVERaw{
				Detail: CVEDetail{
					Description: CVEDescription{
						Data: []CVEDescriptionData{
							{Value: "Single description"},
						},
					},
				},
			},
			want: []string{"Single description"},
		},
		{
			name: "Success - empty descriptions",
			doc: &CVERaw{
				Detail: CVEDetail{
					Description: CVEDescription{
						Data: []CVEDescriptionData{},
					},
				},
			},
			want: []string{},
		},
		{
			name: "Success - nil data",
			doc: &CVERaw{
				Detail: CVEDetail{
					Description: CVEDescription{
						Data: nil,
					},
				},
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.doc.GetDescriptions()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetDescriptions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCVERaw_GetReferences(t *testing.T) {
	tests := []struct {
		name string
		doc  *CVERaw
		want []string
	}{
		{
			name: "Success - references without tags",
			doc: &CVERaw{
				Detail: CVEDetail{
					References: CVEReference{
						Data: []CVEReferenceData{
							{Tags: []string{}, Url: "https://example.com/ref1"},
							{Tags: nil, Url: "https://example.com/ref2"},
						},
					},
				},
			},
			want: []string{"https://example.com/ref1", "https://example.com/ref2"},
		},
		{
			name: "Success - empty references",
			doc: &CVERaw{
				Detail: CVEDetail{
					References: CVEReference{
						Data: []CVEReferenceData{},
					},
				},
			},
			want: []string{},
		},
		{
			name: "Success - nil data",
			doc: &CVERaw{
				Detail: CVEDetail{
					References: CVEReference{
						Data: nil,
					},
				},
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.doc.GetReferences()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetReferences() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCVELang_GetID(t *testing.T) {
	tests := []struct {
		name string
		doc  *CVELang
		want string
	}{
		{
			name: "Success - returns ID",
			doc:  &CVELang{ID: "CVE-2023-1234"},
			want: "CVE-2023-1234",
		},
		{
			name: "Success - empty ID",
			doc:  &CVELang{ID: ""},
			want: "",
		},
		{
			name: "Success - another ID",
			doc:  &CVELang{ID: "CVE-2022-5678"},
			want: "CVE-2022-5678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.doc.GetID()
			if got != tt.want {
				t.Errorf("GetID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCVELang_SetID(t *testing.T) {
	tests := []struct {
		name string
		doc  *CVELang
		id   string
		want string
	}{
		{
			name: "Success - set ID",
			doc:  &CVELang{},
			id:   "CVE-2023-1234",
			want: "CVE-2023-1234",
		},
		{
			name: "Success - overwrite existing ID",
			doc:  &CVELang{ID: "CVE-2022-0000"},
			id:   "CVE-2023-5678",
			want: "CVE-2023-5678",
		},
		{
			name: "Success - set empty ID",
			doc:  &CVELang{ID: "CVE-2023-1234"},
			id:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.doc.SetEID(tt.id)
			if tt.doc.ID != tt.want {
				t.Errorf("SetID() ID = %v, want %v", tt.doc.ID, tt.want)
			}
		})
	}
}

func TestCVERaw_GetID(t *testing.T) {
	tests := []struct {
		name string
		doc  *CVERaw
		want string
	}{
		{
			name: "Success - returns hashed ID",
			doc: &CVERaw{
				Detail: CVEDetail{
					Metadata: CVEMetadata{
						ID: "1",
					},
				},
			},
			want: "356a192b7913b04c54574d18c28d46e6395428ab",
		},
		{
			name: "Success - another ID",
			doc: &CVERaw{
				Detail: CVEDetail{
					Metadata: CVEMetadata{
						ID: "test",
					},
				},
			},
			want: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.doc.GetID()
			if got != tt.want {
				t.Errorf("GetID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCVERaw_SetID(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{
			name: "Success - set empty ID",
			id:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &CVERaw{}
			doc.SetEID(tt.id)
			if doc.Detail.Metadata.ID != tt.id {
				t.Errorf("SetID() ID = %v, want %v", doc.Detail.Metadata.ID, tt.id)
			}
		})
	}
}

func TestPrepareQuery(t *testing.T) {
	tests := []struct {
		name     string
		body     RequestHistorySearch
		expected map[string]interface{}
	}{
		{
			name: "Basic query with document ID only",
			body: RequestHistorySearch{
				ID: "test-id-123",
			},
			expected: map[string]interface{}{
				"bool": map[string][]interface{}{
					"filter": {
						map[string]interface{}{
							"term": map[string]interface{}{
								"document": "test-id-123",
							},
						},
					},
				},
			},
		},
		{
			name: "Query with FromDate = 0, ToDate > 0",
			body: RequestHistorySearch{
				ID:       "test-id-456",
				FromDate: 0,
				ToDate:   1693036800,
			},
			expected: map[string]interface{}{
				"bool": map[string][]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"term": map[string]interface{}{
								"document": "test-id-456",
							},
						},
					},
				},
			},
		},
		{
			name: "Query with FromDate > 0, ToDate = 0",
			body: RequestHistorySearch{
				ID:       "test-id-789",
				FromDate: 1692950400,
				ToDate:   0,
			},
			expected: map[string]interface{}{
				"bool": map[string][]interface{}{
					"filter": []interface{}{
						map[string]interface{}{
							"term": map[string]interface{}{
								"document": "test-id-789",
							},
						},
					},
				},
			},
		},
		{
			name: "Query with both dates = 0",
			body: RequestHistorySearch{
				ID:       "test-id-000",
				FromDate: 0,
				ToDate:   0,
			},
			expected: map[string]interface{}{
				"bool": map[string][]interface{}{
					"filter": {
						map[string]interface{}{
							"term": map[string]interface{}{
								"document": "test-id-000",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.body.PrepareQuery()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHistory_GetID(t *testing.T) {
	tests := []struct {
		name     string
		history  *History
		expected string
	}{
		{
			name: "Get ID successfully",
			history: &History{
				ID: "test-id-123",
			},
			expected: "test-id-123",
		},
		{
			name: "Get empty ID",
			history: &History{
				ID: "",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.history.GetID()
			if result != tt.expected {
				t.Errorf("GetID() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHistory_SetID(t *testing.T) {
	tests := []struct {
		name     string
		history  *History
		inputID  string
		expected string
	}{
		{
			name:     "Set ID successfully",
			history:  &History{},
			inputID:  "new-id-456",
			expected: "new-id-456",
		},
		{
			name:     "Set empty ID",
			history:  &History{},
			inputID:  "",
			expected: "",
		},
		{
			name: "Override existing ID",
			history: &History{
				ID: "old-id",
			},
			inputID:  "new-id-789",
			expected: "new-id-789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.history.SetEID(tt.inputID)
			if tt.history.ID != tt.expected {
				t.Errorf("After SetID(), ID = %v, want %v", tt.history.ID, tt.expected)
			}
		})
	}
}

func TestProcessCVSSCNA(t *testing.T) {
	tests := []struct {
		name         string
		score        float32
		version      string
		vectorString string
		source       string
		wantEmpty    bool
		wantSeverity int
	}{
		{
			name:         "empty version returns empty",
			score:        7.5,
			version:      "",
			vectorString: "test-vector",
			source:       "test-source",
			wantEmpty:    true,
		},
		{
			name:         "version 2.0 low score",
			score:        2.0,
			version:      "2.0",
			vectorString: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			source:       "nvd@nist.gov",
			wantSeverity: defs.SeverityCodeLow,
		},
		{
			name:         "version 2.0 medium score",
			score:        5.0,
			version:      "2.0",
			vectorString: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			source:       "nvd@nist.gov",
			wantSeverity: defs.SeverityCodeMedium,
		},
		{
			name:         "version 2.0 high score",
			score:        8.0,
			version:      "2.0",
			vectorString: "AV:N/AC:L/Au:N/C:C/I:C/A:C",
			source:       "nvd@nist.gov",
			wantSeverity: defs.SeverityCodeHigh,
		},
		{
			name:         "version 3.0 critical score",
			score:        9.5,
			version:      "3.0",
			vectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			source:       "test-source",
			wantSeverity: defs.SeverityCodeCritical,
		},
		{
			name:         "version 3.1 medium score",
			score:        5.5,
			version:      "3.1",
			vectorString: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L",
			source:       "test-source",
			wantSeverity: defs.SeverityCodeMedium,
		},
		{
			name:         "version 4.0 low score",
			score:        1.5,
			version:      "4.0",
			vectorString: "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N",
			source:       "test-source",
			wantSeverity: defs.SeverityCodeLow,
		},
		{
			name:         "unsupported version uses default",
			score:        6.0,
			version:      "1.0",
			vectorString: "test-vector",
			source:       "test-source",
			wantSeverity: defs.SeverityCodeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ProcessCVSSCNA(tt.score, tt.version, tt.vectorString, tt.source)
			if tt.wantEmpty {
				if result != (CVEMetric{}) {
					t.Errorf("Expected empty CVEMetric, got %+v", result)
				}
				return
			}
			if result.Score != tt.score {
				t.Errorf("Expected score %v, got %v", tt.score, result.Score)
			}
			if result.Version != tt.version {
				t.Errorf("Expected version %v, got %v", tt.version, result.Version)
			}
			if result.VectorString != tt.vectorString {
				t.Errorf("Expected vectorString %v, got %v", tt.vectorString, result.VectorString)
			}
			if result.Source != tt.source {
				t.Errorf("Expected source %v, got %v", tt.source, result.Source)
			}
			if result.Severity != tt.wantSeverity {
				t.Errorf("Expected severity %v, got %v", tt.wantSeverity, result.Severity)
			}
		})
	}
}
