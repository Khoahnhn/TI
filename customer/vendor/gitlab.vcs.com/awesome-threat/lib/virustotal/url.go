package virustotal

import "gitlab.viettelcyber.com/awesome-threat/library/slice"

type (
	URL struct {
		ID         string            `json:"id"`
		Type       string            `json:"type"`
		Links      map[string]string `json:"links"`
		Attributes AttributesURL     `json:"attributes"`
	}

	AttributesURL struct {
		Categories                    map[string]string          `json:"categories"`
		Favicon                       map[string]string          `json:"favicon"`
		FirstSubmissionDate           int64                      `json:"first_submission_date"`
		HTMLMeta                      map[string]interface{}     `json:"html_meta"`
		LastAnalysisDate              int64                      `json:"last_analysis_date"`
		LastAnalysisResults           map[string]*AnalysisResult `json:"last_analysis_results"`
		LastAnalysisStats             *AnalysisStats             `json:"last_analysis_stats"`
		LastHTTPResponseCode          int                        `json:"last_http_response_code"`
		LastHTTPResponseContentLength int                        `json:"last_http_response_content_length"`
		LastHTTPResponseContentSHA256 string                     `json:"last_http_response_content_sha256"`
		LastHTTPResponseCookies       map[string]string          `json:"last_http_response_cookies"`
		LastHTTPResponseHeaders       map[string]string          `json:"last_http_response_headers"`
		LastModificationDate          int64                      `json:"last_modification_date"`
		LastSubmissionDate            int64                      `json:"last_submission_date"`
		OutgoingLinks                 []string                   `json:"outgoing_links"`
		RedirectionChain              []string                   `json:"redirection_chain"`
		Reputation                    int                        `json:"reputation"`
		Tags                          []string                   `json:"tags"`
		TargetedBrand                 map[string]interface{}     `json:"targeted_brand"`
		TimesSubmitted                int                        `json:"times_submitted"`
		Title                         string                     `json:"title"`
		TotalVotes                    map[string]int             `json:"total_votes"`
		Trackers                      map[string][]Tracker       `json:"trackers"`
		URL                           string                     `json:"url"`
	}

	Tracker struct {
		ID        string `json:"id"`
		Timestamp int64  `json:"timestamp"`
		URL       string `json:"url"`
	}
)

func (obj *URL) GetID() string {
	return obj.ID
}

func (obj *URL) Evaluate(trustAVs []string, trustAVThreshold, scoreThreshold int) int {
	actualScore := 0
	actualTrustAVs := make([]string, 0)
	actualUntrustAVs := make([]string, 0)
	for _, result := range obj.Attributes.LastAnalysisResults {
		if result != nil {
			if result.Result == string(CategoryMalicious) {
				if slice.String(trustAVs).Contains(result.EngineName) {
					actualTrustAVs = append(actualTrustAVs, result.EngineName)
					actualScore += 100
				} else {
					actualUntrustAVs = append(actualUntrustAVs, result.EngineName)
					actualScore += 50
				}
			}
		}
	}
	if len(actualTrustAVs) >= trustAVThreshold {
		return 90
	}
	if actualScore >= scoreThreshold {
		return 80
	} else if actualScore > 0 {
		return 50
	}
	return 10
}
