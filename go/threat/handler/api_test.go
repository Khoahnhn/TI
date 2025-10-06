package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

func Start() CVEHandlerInterface {
	configFile := "../config.yaml"
	f, err := os.Open(configFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var conf *model.Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&conf)
	if err != nil {
		log.Fatal(err)
	}
	cveHandler := NewCVEHandler(*conf, true)
	return cveHandler
}

func TestCVEHandler_ExportCveById(t *testing.T) {
	t.Skip("Legacy test - skip trong nhánh order/os-17")
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}
	cve := Start()
	e.GET("/:id/export-cve", cve.ExportCveById)

	type (
		testCaseInput string
	)

	testCases := []struct {
		name  string
		input testCaseInput
		code  int
	}{
		{
			name:  "1: Bad request",
			input: testCaseInput("CVE-202646-4527"),
			code:  400,
		},
		{
			name:  "2: Internal Server Error",
			input: testCaseInput("CVE-2023-45276"),
			code:  404,
		},
		{
			name:  "3: Success",
			input: testCaseInput("CVE-2023-4527"),
			code:  200,
		},
	}

	for _, v := range testCases {
		t.Run(v.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/%v/export-cve?lang=vi", v.input), nil)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			res := httptest.NewRecorder()
			e.ServeHTTP(res, req)

			if ok := assert.Equal(t, v.code, res.Code); !ok {
				t.Fatalf("Test fail, exp: %v, got: %v", v.code, res.Code)
			}
			t.Logf("Test case: %v passed", v.name)
		})
	}
}

func TestCVEHandler_ExportListExcelCVE(t *testing.T) {
	t.Skip("Legacy test - skip trong nhánh order/os-17")
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}
	cve := Start()
	e.POST("/export", cve.ExportListCve)

	type (
		testCaseInput model.RequestExport
	)

	testCases := []struct {
		name  string
		input testCaseInput
		code  int
	}{
		{
			name: "1: Bad request",
			input: testCaseInput{
				Ids: nil,
				Req: model.RequestCVESearch{
					Keyword: "",
					Checker: "",
					Severity: model.RequestCVESeverity{
						VTI: model.RequestCVESeverityVerbose{
							Version: "2.0",
							Value:   nil,
						},
						Global: model.RequestCVESeverityVerboseV2{
							Version:          nil,
							SeverityVersion2: nil,
							SeverityVersion3: nil,
						},
					},
					Status:    nil,
					Languages: nil,
					Time:      model.CVESearchTime{},
					Sort:      nil,
					Size:      0,
					Offset:    0,
				},
			},
			code: 400,
		},
		{
			name: "2: Internal Server Error",
			input: testCaseInput{
				Ids: []string{
					"12345",
				},
			},
			code: 404,
		},
		{
			name: "3: Success with filter",
			input: testCaseInput{
				Ids: []string{},
				Req: model.RequestCVESearch{
					Keyword: "",
					Checker: "",
					Severity: model.RequestCVESeverity{
						VTI: model.RequestCVESeverityVerbose{
							Version: "",
							Value:   []int{2},
						},
						Global: model.RequestCVESeverityVerboseV2{
							Version:          []string{"3.*"},
							SeverityVersion2: []int{3},
							SeverityVersion3: []int{3},
						},
					},
					Status:    nil,
					Languages: nil,
					Time:      model.CVESearchTime{},
					Sort:      nil,
					Size:      20,
					Offset:    0,
				},
			},
			code: 200,
		},
		{
			name: "4: Success with ids",
			input: testCaseInput{
				Ids: []string{
					"7da38567e04aff5c7b6e1ed9ac41a252938bdbad",
					"a4d5e1a07d4fdedb1e04dd6a782249c257b14cd4",
					"0926b11a2cca6a2f8b5a1d0311301f76fe0273f3",
				},
			},
			code: 200,
		},
	}

	for _, v := range testCases {
		t.Run(v.name, func(t *testing.T) {
			jsonInput, err := json.Marshal(&v.input)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			req, err := http.NewRequest(http.MethodPost, "/export", bytes.NewBuffer(jsonInput))
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			res := httptest.NewRecorder()
			e.ServeHTTP(res, req)

			if ok := assert.Equal(t, v.code, res.Code); !ok {
				t.Fatalf("Test fail, exp: %v, got: %v", v.code, res.Code)
			}
			t.Logf("Test case: %v passed", v.name)
		})
	}
}

func TestCVEHandler_Create(t *testing.T) {
	t.Skip("Legacy test - skip trong nhánh order/os-17")
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}
	cve := Start()
	e.POST("/create", cve.Create, ExtractToken)
	type (
		testCaseInput model.RequestCVECreate
	)
	testCases := []struct {
		name  string
		input testCaseInput
		code  int
	}{
		{
			name: "1: Bad request",
			input: testCaseInput{
				ID:          "cve-11",
				Published:   1,
				Match:       nil,
				Description: "",
				Reference:   "",
				Patch:       "",
				CVSS: model.CVSSMetric{
					CVSS3: model.CVEMetric{
						Score:        7,
						Version:      "3.1",
						Severity:     1,
						VectorString: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H",
					},
				},
				Lang: "",
			},
			code: 400,
		},
		{
			name: "2: internal server",
			input: testCaseInput{
				ID:          "CVE-2024-2046",
				Published:   1711005312622,
				Match:       []string{},
				Description: "<p>r</p>",
				Reference:   "d",
				Patch:       "d",
				CVSS:        model.CVSSMetric{},
				Lang:        "",
			},
			code: 500,
		},
		{
			name: "3: Create success",
			input: testCaseInput{
				ID:        "CVE-2024-2046",
				Published: 1711005312622,
				Match: []string{
					"cpe:2.3:a:microsoft:azure_kubernetes_service:-:*:*:*:*:*:*:*",
					"cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*",
					"cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*",
				},
				Description: "<p>r</p>",
				Reference:   "d",
				Patch:       "d",
				CVSS: model.CVSSMetric{
					CVSS3: model.CVEMetric{
						Score:        7,
						Version:      "3.1",
						Severity:     1,
						VectorString: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H",
					},
					CVSS4: model.CVEMetric{
						Score:        7,
						Version:      "4.0",
						Severity:     1,
						VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:P",
					},
				},
				CWE: []model.CWEMetric{
					{
						ID:   "CWE-79",
						Name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
						Link: "https://cwe.mitre.org/data/definitions/79.html",
					},
				},
				Lang: "",
			},
			code: 200,
		},
		{
			name: "4: create cve with organization banking",
			input: testCaseInput{
				ID:        "CVE-2024-2046",
				Published: 1711005312622,
				Match: []string{
					"cpe:2.3:o:debian:debian_linux:1.1:*:*:*:*:*:*:*",
				},
				Description: "<p>r</p>",
				Reference:   "d",
				Patch:       "d",
				CVSS:        model.CVSSMetric{},
				Lang:        "",
				CWE: []model.CWEMetric{
					{
						ID:   "CWE-79",
						Name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
						Link: "https://cwe.mitre.org/data/definitions/79.html",
					},
				},
			},
			code: 200,
		},
		{
			name: "5: create cve with organization banking",
			input: testCaseInput{
				ID:        "CVE-2024-2046",
				Published: 1711005312622,
				Match: []string{
					"cpe:2.3:a:apple:safari:*:*:*:*:*:*:*:*",
					"cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*",
					"cpe:2.3:o:apple:ipados:17.0:*:*:*:*:*:*:*",
					"cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*",
					"cpe:2.3:o:apple:iphone_os:17.0:*:*:*:*:*:*:*",
					"cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*",
					"cpe:2.3:o:fedoraproject:fedora:37:*:*:*:*:*:*:*",
					"cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*",
					"cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*",
					"cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
					"cpe:2.3:o:debian:debian_linux:12.0:*:*:*:*:*:*:*",
				},
				Description: "<p>r</p>",
				Reference:   "d",
				Patch:       "d",
				CVSS:        model.CVSSMetric{},
				Lang:        "",
				CWE: []model.CWEMetric{
					{
						ID:   "CWE-79",
						Name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
						Link: "https://cwe.mitre.org/data/definitions/79.html",
					},
				},
			},
			code: 200,
		},
	}
	for _, v := range testCases {
		t.Run(v.name, func(t *testing.T) {
			jsonInput, err := json.Marshal(v.input)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}

			req, err := http.NewRequest(http.MethodPost, "/create", bytes.NewBuffer(jsonInput))
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Cookie", "username=chiendd3; request_state=8558e54e-3da8-4a21-9561-7f9c5e51e7bd; access_token_cookie=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJWMmZrMjd0RkwxZ01mQjJhNVgyTkNVYkdGRjNDMG5YVGM3c2hGZmxCdU5BIn0.eyJleHAiOjE3MTEwMTA5MTYsImlhdCI6MTcxMTAwOTExNiwiYXV0aF90aW1lIjoxNzExMDA5MTE2LCJqdGkiOiIzOTc4ZjBmMi0xYmJiLTQ3YWEtOTQ2ZS1lMjI0MGQ2YTJmZDEiLCJpc3MiOiJodHRwOi8vYXV0aC12My5qdXBpdGVyLnBsYXRmb3JtLnRpLnZpc2MuY29tL2F1dGgvcmVhbG1zL29wZXJhdGlvbi12MyIsImF1ZCI6WyJ2dGkiLCJhY2NvdW50Il0sInN1YiI6IjAxMjgwMzViLWNlM2EtNDIwMy1iMmYzLThiNDU3YTFkYzYxZSIsInR5cCI6IkJlYXJlciIsImF6cCI6InZ0aSIsInNlc3Npb25fc3RhdGUiOiIzNjE2NjMwNS0yNDg0LTRlZWMtOWIxMy00MGM2YzFmNjM5YmYiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwiZGVmYXVsdC1yb2xlcy1vcGVyYXRpb24tdjMiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgYXVkaWVuY2UgZW1haWwgZ3JvdXAiLCJzaWQiOiIzNjE2NjMwNS0yNDg0LTRlZWMtOWIxMy00MGM2YzFmNjM5YmYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiLEkOG7lyBDaGnhur9uIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiY2hpZW5kZDMiLCJnaXZlbl9uYW1lIjoixJDhu5ciLCJmYW1pbHlfbmFtZSI6IkNoaeG6v24iLCJlbWFpbCI6ImNoaWVuZGQzQHZpZXR0ZWwuY29tLnZuIiwiZ3JvdXAiOltdfQ.SrWWMgq9a14hjoad19pPRli_BCiDh9kC4KBQ6rPZWbG8yeYi21Wzhb8AnSztRzPKTits58ZzORYv4c7we3-u4i4okKkavy5ykuASjwfRQfCvyycf5qa9WavMg9fdnkui3XwozvrfTOBKGzjkjSxHWGF279SV_wBZSjWmwpYF0SqCN1RCgwR3f8vhaVRSIOWH2MO29YgMh_B04CNjDRFFk-SLRDioh7uOOVixVIK3NpsAkhLZuPgfWzbbXPG2b6s2p9V2AngPfrnVZpX4hEYZafne2PdcAhUgiH-bpo70RZ3j9u0YmqwNUPF_4DV2gLF1i2uHv0_4ifY1aSSDmMCjZg; refresh_token_cookie=5wH2Oba1HvjBQhnbYktZPBXjOXiWCD6tR0B2KXLDXRk12rl9JacteyA7fEAGhdDsUNx/OZ7SFbVzrhtZaj4TlMq4XgpHU6rXdyqApbSW2JXRfP7Sv6Aale9cVv8blU40sxAUuQZCArXzw8lC9MuJzhZauzy87wldTxnBzlvLp4mWp9dnc5RHLVRUiz1L2A79c7dLW4QixRL+IG3RzXZbZFVi78oIIkGhcqa+vLQqYip3h7con9HIOY31LYwU9aRqNnGnV9Jf6MKIsv9AYyrX81pG11964441IARAnjwHmEbH6J1xTMRIYxmoN/MaLAx4T4uk/yXNtV+3jq5KyVXKj6XagCR5gZcaA+WIKgtOmWupWFfCejMLEqly13IXzqOd+GGrqJBWtSiJ3qdEkeVX9VvIcQN9eXH5won0jqol6BRkDhvLa/Om7Olu+DovnRpmnymTTbhdmMoj7jKeKCtvGeouDy3Lg6LzRkp+VKL0h+D8OuKjKvAvGqwEWqIK0G4Baeqi4MVqvB3zGsuu7hSiL0Oq3hL+/wVBGPDFXLIsDl2KRS62ZW+9LHrdtLRozn2EGTW+FaZL0EU9oJvlEN4tXkQ9OmOFxaLhvsobaqc8P90p2EyM8Jg7TfjHEc88Q+d9ICxzVaANP+MjGEZ5fapWMvo+jpD/6l89tsFhBTJZ7GkugCeuXsoYc0ox600TlH/WUNYRhsfrkiVP38BU86Vp16I4+mavzlMyeulvNq/PRos+YM+acGDU50OsgS7enZWnjKOSbb1OqTyCrqsKIgxfOwFA99KKhM5mNm4")
			res := httptest.NewRecorder()
			e.ServeHTTP(res, req)
			if ok := assert.Equal(t, v.code, res.Code); !ok {
				t.Fatalf("Test fail, exp: %v, got: %v", v.code, res.Code)
			}
			t.Logf("Test case: %v passed", v.name)
		})
	}
}

func TestCVEHandler_Edit(t *testing.T) {
	t.Skip("Legacy test - skip trong nhánh order/os-17")
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}
	cve := Start()
	e.POST("/edit", cve.Edit, ExtractToken)
	type (
		testCaseInput model.RequestCVEEdit
	)
	testCases := []struct {
		name  string
		input testCaseInput
		code  int
	}{
		{
			name: "1: Bad request",
			input: testCaseInput{
				ID:          "cve-11",
				Published:   1,
				Match:       nil,
				Description: "",
				Reference:   "",
				Patch:       "",
				CVSS: model.CVSSMetric{
					CVSS3: model.CVEMetric{
						Score:        7,
						Version:      "3.1",
						Severity:     1,
						VectorString: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H",
					},
					CVSS4: model.CVEMetric{
						Score:        7,
						Version:      "4.0",
						Severity:     1,
						VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:P",
					},
				},
				CWE: []model.CWEMetric{
					{
						ID:   "CWE-79",
						Name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
						Link: "https://cwe.mitre.org/data/definitions/79.html",
					},
				},
				Lang: "en",
			},
			code: 400,
		},
		{
			name: "2: internal server",
			input: testCaseInput{
				ID:          "CVE-2024-2046",
				Published:   1711005312622,
				Match:       []string{},
				Description: "<p>r</p>",
				Reference:   "d",
				Patch:       "d",
				CVSS:        model.CVSSMetric{},
				Lang:        "en",
			},
			code: 500,
		},
		{
			name: "3: edit success",
			input: testCaseInput{
				ID:        "CVE-2024-2046",
				Published: 1711005312622,
				Match: []string{
					"cpe:2.3:a:microsoft:azure_kubernetes_service:-:*:*:*:*:*:*:*",
					"cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*",
					"cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*",
				},
				Description: "<p>r</p>",
				Reference:   "d",
				Patch:       "d",
				CVSS: model.CVSSMetric{
					CVSS3: model.CVEMetric{
						Score:        7,
						Version:      "3.1",
						Severity:     1,
						VectorString: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H",
					},
					CVSS4: model.CVEMetric{
						Score:        7,
						Version:      "4.0",
						Severity:     1,
						VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:P",
					},
				},
				CWE: []model.CWEMetric{
					{
						ID:   "CWE-79",
						Name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
						Link: "https://cwe.mitre.org/data/definitions/79.html",
					},
				},
				Lang: "en",
			},
			code: 200,
		},
		{
			name: "4: edit cve with organization banking",
			input: testCaseInput{
				ID:        "CVE-2024-2046",
				Published: 1711005312622,
				Match: []string{
					"cpe:2.3:o:debian:debian_linux:1.1:*:*:*:*:*:*:*",
				},
				Description: "<p>r</p>",
				Reference:   "d",
				Patch:       "d",
				CVSS:        model.CVSSMetric{},
				Lang:        "en",
				CWE: []model.CWEMetric{
					{
						ID:   "CWE-79",
						Name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
						Link: "https://cwe.mitre.org/data/definitions/79.html",
					},
				},
			},
			code: 200,
		},
		{
			name: "5: edit cve with organization banking",
			input: testCaseInput{
				ID:        "CVE-2024-2046",
				Published: 1711005312622,
				Match: []string{
					"cpe:2.3:a:apple:safari:*:*:*:*:*:*:*:*",
					"cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*",
					"cpe:2.3:o:apple:ipados:17.0:*:*:*:*:*:*:*",
					"cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*",
					"cpe:2.3:o:apple:iphone_os:17.0:*:*:*:*:*:*:*",
					"cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*",
					"cpe:2.3:o:fedoraproject:fedora:37:*:*:*:*:*:*:*",
					"cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*",
					"cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*",
					"cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
					"cpe:2.3:o:debian:debian_linux:12.0:*:*:*:*:*:*:*",
				},
				Description: "<p>r</p>",
				Reference:   "d",
				Patch:       "d",
				CVSS:        model.CVSSMetric{},
				Lang:        "en",
				CWE: []model.CWEMetric{
					{
						ID:   "CWE-79",
						Name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
						Link: "https://cwe.mitre.org/data/definitions/79.html",
					},
				},
			},
			code: 200,
		},
	}
	for _, v := range testCases {
		t.Run(v.name, func(t *testing.T) {
			jsonInput, err := json.Marshal(v.input)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}

			req, err := http.NewRequest(http.MethodPost, "/edit", bytes.NewBuffer(jsonInput))
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Cookie", "username=chiendd3; request_state=8558e54e-3da8-4a21-9561-7f9c5e51e7bd; access_token_cookie=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJWMmZrMjd0RkwxZ01mQjJhNVgyTkNVYkdGRjNDMG5YVGM3c2hGZmxCdU5BIn0.eyJleHAiOjE3MTEwMTA5MTYsImlhdCI6MTcxMTAwOTExNiwiYXV0aF90aW1lIjoxNzExMDA5MTE2LCJqdGkiOiIzOTc4ZjBmMi0xYmJiLTQ3YWEtOTQ2ZS1lMjI0MGQ2YTJmZDEiLCJpc3MiOiJodHRwOi8vYXV0aC12My5qdXBpdGVyLnBsYXRmb3JtLnRpLnZpc2MuY29tL2F1dGgvcmVhbG1zL29wZXJhdGlvbi12MyIsImF1ZCI6WyJ2dGkiLCJhY2NvdW50Il0sInN1YiI6IjAxMjgwMzViLWNlM2EtNDIwMy1iMmYzLThiNDU3YTFkYzYxZSIsInR5cCI6IkJlYXJlciIsImF6cCI6InZ0aSIsInNlc3Npb25fc3RhdGUiOiIzNjE2NjMwNS0yNDg0LTRlZWMtOWIxMy00MGM2YzFmNjM5YmYiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwiZGVmYXVsdC1yb2xlcy1vcGVyYXRpb24tdjMiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgYXVkaWVuY2UgZW1haWwgZ3JvdXAiLCJzaWQiOiIzNjE2NjMwNS0yNDg0LTRlZWMtOWIxMy00MGM2YzFmNjM5YmYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiLEkOG7lyBDaGnhur9uIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiY2hpZW5kZDMiLCJnaXZlbl9uYW1lIjoixJDhu5ciLCJmYW1pbHlfbmFtZSI6IkNoaeG6v24iLCJlbWFpbCI6ImNoaWVuZGQzQHZpZXR0ZWwuY29tLnZuIiwiZ3JvdXAiOltdfQ.SrWWMgq9a14hjoad19pPRli_BCiDh9kC4KBQ6rPZWbG8yeYi21Wzhb8AnSztRzPKTits58ZzORYv4c7we3-u4i4okKkavy5ykuASjwfRQfCvyycf5qa9WavMg9fdnkui3XwozvrfTOBKGzjkjSxHWGF279SV_wBZSjWmwpYF0SqCN1RCgwR3f8vhaVRSIOWH2MO29YgMh_B04CNjDRFFk-SLRDioh7uOOVixVIK3NpsAkhLZuPgfWzbbXPG2b6s2p9V2AngPfrnVZpX4hEYZafne2PdcAhUgiH-bpo70RZ3j9u0YmqwNUPF_4DV2gLF1i2uHv0_4ifY1aSSDmMCjZg; refresh_token_cookie=5wH2Oba1HvjBQhnbYktZPBXjOXiWCD6tR0B2KXLDXRk12rl9JacteyA7fEAGhdDsUNx/OZ7SFbVzrhtZaj4TlMq4XgpHU6rXdyqApbSW2JXRfP7Sv6Aale9cVv8blU40sxAUuQZCArXzw8lC9MuJzhZauzy87wldTxnBzlvLp4mWp9dnc5RHLVRUiz1L2A79c7dLW4QixRL+IG3RzXZbZFVi78oIIkGhcqa+vLQqYip3h7con9HIOY31LYwU9aRqNnGnV9Jf6MKIsv9AYyrX81pG11964441IARAnjwHmEbH6J1xTMRIYxmoN/MaLAx4T4uk/yXNtV+3jq5KyVXKj6XagCR5gZcaA+WIKgtOmWupWFfCejMLEqly13IXzqOd+GGrqJBWtSiJ3qdEkeVX9VvIcQN9eXH5won0jqol6BRkDhvLa/Om7Olu+DovnRpmnymTTbhdmMoj7jKeKCtvGeouDy3Lg6LzRkp+VKL0h+D8OuKjKvAvGqwEWqIK0G4Baeqi4MVqvB3zGsuu7hSiL0Oq3hL+/wVBGPDFXLIsDl2KRS62ZW+9LHrdtLRozn2EGTW+FaZL0EU9oJvlEN4tXkQ9OmOFxaLhvsobaqc8P90p2EyM8Jg7TfjHEc88Q+d9ICxzVaANP+MjGEZ5fapWMvo+jpD/6l89tsFhBTJZ7GkugCeuXsoYc0ox600TlH/WUNYRhsfrkiVP38BU86Vp16I4+mavzlMyeulvNq/PRos+YM+acGDU50OsgS7enZWnjKOSbb1OqTyCrqsKIgxfOwFA99KKhM5mNm4")
			res := httptest.NewRecorder()
			e.ServeHTTP(res, req)
			if ok := assert.Equal(t, v.code, res.Code); !ok {
				t.Fatalf("Test fail, exp: %v, got: %v", v.code, res.Code)
			}
			t.Logf("Test case: %v passed", v.name)
		})
	}
}

func TestCVEHandler_EPSSHistory(t *testing.T) {
	t.Skip("Legacy test - skip trong nhánh order/os-17")
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}
	cve := Start()
	e.GET("/:id/history-epss", cve.EPSSHistory)

	type (
		testCaseInput string
	)

	testCases := []struct {
		name  string
		input testCaseInput
		code  int
	}{
		{
			name:  "1: Bad request",
			input: testCaseInput("CVE-202646-4527"),
			code:  400,
		},
		{
			name:  "2: Internal Server Error",
			input: testCaseInput("CVE-2023-45276"),
			code:  404,
		},
		{
			name:  "3: Success",
			input: testCaseInput("CVE-2023-4527"),
			code:  200,
		},
	}

	for _, v := range testCases {
		t.Run(v.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/%v/history-epss", v.input), nil)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			res := httptest.NewRecorder()
			e.ServeHTTP(res, req)

			if ok := assert.Equal(t, v.code, res.Code); !ok {
				t.Fatalf("Test fail, exp: %v, got: %v", v.code, res.Code)
			}
			t.Logf("Test case: %v passed", v.name)
		})
	}
}
