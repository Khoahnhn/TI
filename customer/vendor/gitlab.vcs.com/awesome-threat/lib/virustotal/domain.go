package virustotal

type (
	DomainV3 struct {
		ID         string            `json:"id,omitempty"`
		Type       string            `json:"type,omitempty"`
		Links      map[string]string `json:"links,omitempty"`
		Attributes AttributesDomain  `json:"attributes,omitempty"`
	}

	AttributesDomain struct {
		Categories               map[string]string                 `json:"categories,omitempty"`
		CreationDate             int64                             `json:"creation_date,omitempty"`
		Favicon                  map[string]string                 `json:"favicon,omitempty"`
		JARM                     string                            `json:"jarm,omitempty"`
		LastAnalysisDate         int64                             `json:"last_analysis_date,omitempty"`
		LastAnalysisResults      map[string]*AnalysisResult        `json:"last_analysis_results,omitempty"`
		LastAnalysisStats        *AnalysisStats                    `json:"last_analysis_stats,omitempty"`
		LastDNSRecords           []map[string]interface{}          `json:"last_dns_records,omitempty"`
		LastDNSRecordsDate       int64                             `json:"last_dns_records_date,omitempty"`
		LastHTTPSCertificate     *SSLCertificate                   `json:"last_https_certificate,omitempty"`
		LastHTTPSCertificateDate int64                             `json:"last_https_certificate_date,omitempty"`
		LastModificationDate     int64                             `json:"last_modification_date,omitempty"`
		LastUpdateDate           int64                             `json:"last_update_date,omitempty"`
		PopularityRanks          map[string]map[string]interface{} `json:"popularity_ranks,omitempty"`
		Registrar                string                            `json:"registrar,omitempty"`
		Reputation               int                               `json:"reputation,omitempty"`
		Tags                     []string                          `json:"tags,omitempty"`
		TotalVotes               map[string]int                    `json:"total_votes,omitempty"`
		Whois                    string                            `json:"whois,omitempty"`
		WhoisDate                int64                             `json:"whois_date,omitempty"`
	}
)

func (obj *DomainV3) GetID() string {
	return obj.ID
}

//func (obj *DomainV3) Evaluate(trustAVs []string, trustAVThreshold, scoreThreshold int) int {
//	actualScore := 0
//	actualTrustAVs := make([]string, 0)
//	actualUntrustAVs := make([]string, 0)
//	for _, result := range obj.Attributes.LastAnalysisResults {
//		if result != nil {
//			if result.Result == string(CategoryMalicious) {
//				if slice.String(trustAVs).Contains(result.EngineName) {
//					actualTrustAVs = append(actualTrustAVs, result.EngineName)
//					actualScore += 100
//				} else {
//					actualUntrustAVs = append(actualUntrustAVs, result.EngineName)
//					actualScore += 50
//				}
//			}
//		}
//	}
//	if len(actualTrustAVs) >= trustAVThreshold {
//		return 90
//	}
//	if actualScore >= scoreThreshold {
//		return 80
//	} else if actualScore > 0 {
//		return 50
//	}
//	return 10
//}
