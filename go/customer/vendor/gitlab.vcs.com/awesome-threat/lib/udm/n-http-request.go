package udm

import "gitlab.viettelcyber.com/awesome-threat/library/rest"

type (
	HTTPRequest struct {
		URL        string                 `json:"url,omitempty"`
		Method     HTTPMethod             `json:"method,omitempty"`
		Proto      string                 `json:"proto,omitempty"`
		Request    *NetworkRequest        `json:"request,omitempty"`
		Response   *NetworkResponse       `json:"response,omitempty"`
		Flat       map[string]interface{} `json:"flat,omitempty"`
		ScanResult *HTTPRequestScanResult `json:"scan_result,omitempty"`
	}

	NetworkRequest struct {
		Time      int64             `json:"time,omitempty"`
		Headers   map[string]string `json:"headers,omitempty"`
		Payload   string            `json:"payload,omitempty"`
		Useragent string            `json:"useragent,omitempty"`
	}

	NetworkResponse struct {
		Time          int64             `json:"time,omitempty"`
		Status        string            `json:"status,omitempty"`
		StatusCode    int               `json:"status_code,omitempty"`
		ContentType   string            `json:"content_type,omitempty"`
		ContentLength int64             `json:"content_length,omitempty"`
		BodyLength    int64             `json:"body_length,omitempty"`
		Headers       map[string]string `json:"headers,omitempty"`
		Content       string            `json:"content,omitempty"`
	}

	HTTPRequestScanResult struct {
		MissingStrictTransportSecurity   bool `json:"missing_strict_transport_security"`
		MissingXContentTypeOptions       bool `json:"missing_x_content_type_options"`
		MissingXFrameOptions             bool `json:"missing_x_frame_options"`
		MissingXXSSProtection            bool `json:"missing_x_xss_protection"`
		MissingCacheControl              bool `json:"missing_cache_control"`
		InsecureAccessControlAllowOrigin bool `json:"insecure_access_control_allow_origin"`
	}
)

func (inst *HTTPRequest) Flatten() map[string]interface{} {
	flattened := make(map[string]interface{})
	flattened["Request URL"] = inst.URL
	flattened["Request Method"] = inst.Method
	flattened["Proto"] = inst.Proto
	flattened["Status Code"] = "N/A"
	flattened["Response Content Type"] = "N/A"
	flattened["Response Content Length"] = "N/A"
	flattened["Response Body Length"] = "N/A"
	flattened["Response Headers"] = map[string]interface{}{}
	if inst.Response != nil {
		if inst.Response.Status != "" {
			flattened["Status Code"] = inst.Response.Status
		}
		if inst.Response.Headers != nil {
			if inst.Response.ContentType != "" {
				flattened["Response Content Type"] = inst.Response.Content
			}
			if inst.Response.ContentLength > 0 {
				flattened["Response Content Length"] = inst.Response.ContentLength
			}
			if inst.Response.BodyLength > 0 {
				flattened["Response Body Length"] = inst.Response.BodyLength
			}
			flattened["Response Headers"] = inst.Response.Headers
		}
	}
	flattened["User Agent"] = "N/A"
	flattened["Request Headers"] = map[string]interface{}{}
	if inst.Request.Useragent != "" {
		flattened["User Agent"] = inst.Request.Useragent
	}
	if inst.Request != nil {
		if inst.Request.Headers != nil {
			flattened["Request Headers"] = inst.Request.Headers
		}
	}
	// Success
	return flattened
}

func (inst *HTTPRequest) Scan() {
	inst.ScanResult = &HTTPRequestScanResult{}
	if inst.Response != nil {
		if inst.Response.Headers != nil && inst.Response.StatusCode < rest.StatusBadRequest {
			// Missing Strict Transport Security
			if _, ok := inst.Response.Headers[rest.HeaderStrictTransportSecurity]; !ok {
				inst.ScanResult.MissingStrictTransportSecurity = true
			}
			// Missing X-Content-Type-Options
			if _, ok := inst.Response.Headers[rest.HeaderXContentTypeOptions]; !ok {
				inst.ScanResult.MissingXContentTypeOptions = true
			}
			// Missing X-Frame-Options
			if _, ok := inst.Response.Headers[rest.HeaderXFrameOptions]; !ok {
				inst.ScanResult.MissingXFrameOptions = true
			}
			// Missing X-XSS-Protection
			if _, ok := inst.Response.Headers[rest.HeaderXXSSProtection]; !ok {
				inst.ScanResult.MissingXXSSProtection = true
			}
			// Missing Cache-Control
			if _, ok := inst.Response.Headers[rest.HeaderCacheControl]; !ok {
				inst.ScanResult.MissingCacheControl = true
			}
			// Insecure Access Control Allow Origin
			if value, ok := inst.Response.Headers[rest.HeaderAccessControlAllowOrigin]; !ok {
				inst.ScanResult.InsecureAccessControlAllowOrigin = true
			} else {
				if value != "*" {
					inst.ScanResult.InsecureAccessControlAllowOrigin = true
				}
			}
		}
	}
}

func (inst *HTTPRequest) ScanSummary() []string {
	summaries := make([]string, 0)
	if inst.ScanResult != nil {
		if inst.ScanResult.MissingStrictTransportSecurity {
			summaries = append(summaries, "Missing Strict-Transport-Security")
		}
		if inst.ScanResult.MissingXContentTypeOptions {
			summaries = append(summaries, "Missing X-Content-Type-Options")
		}
		if inst.ScanResult.MissingXFrameOptions {
			summaries = append(summaries, "Missing X-Frame-Options")
		}
		if inst.ScanResult.MissingXXSSProtection {
			summaries = append(summaries, "Missing X-XSS-Protection")
		}
		if inst.ScanResult.MissingCacheControl {
			summaries = append(summaries, "Missing Cache-Control")
		}
		if inst.ScanResult.InsecureAccessControlAllowOrigin {
			summaries = append(summaries, "Insecure Access-Control-Allow-Origin")
		}
	}
	// Success
	return summaries
}
