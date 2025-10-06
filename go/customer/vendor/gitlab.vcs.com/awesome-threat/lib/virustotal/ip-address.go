package virustotal

type (
	IPAddressV3 struct {
		ID         string                `json:"id,omitempty"`
		Type       string                `json:"type,omitempty"`
		Links      map[string]string     `json:"links,omitempty"`
		Attributes *IPAddressV3Attribute `json:"attributes,omitempty"`
	}

	IPAddressV3Attribute struct {
		AsOwner                  string                     `json:"as_owner,omitempty"`
		ASN                      int                        `json:"asn,omitempty"`
		Continent                string                     `json:"continent,omitempty"`
		Country                  string                     `json:"country,omitempty"`
		JARM                     string                     `json:"jarm,omitempty"`
		LastAnalysisDate         int64                      `json:"last_analysis_date,omitempty"`
		LastAnalysisResults      map[string]*AnalysisResult `json:"last_analysis_results,omitempty"`
		LastAnalysisStats        *AnalysisStats             `json:"last_analysis_stats,omitempty"`
		LastHTTPSCertificate     *SSLCertificate            `json:"last_https_certificate,omitempty"`
		LastHTTPSCertificateDate int64                      `json:"last_https_certificate_date,omitempty"`
		LastModificationDate     int64                      `json:"last_modification_date,omitempty"`
		Network                  string                     `json:"network,omitempty"`
		RegionalInternetRegistry string                     `json:"regional_internet_registry,omitempty"`
		Reputation               int                        `json:"reputation,omitempty"`
		Tags                     []string                   `json:"tags,omitempty"`
		TotalVotes               map[string]int             `json:"total_votes,omitempty"`
		Whois                    string                     `json:"whois,omitempty"`
		WhoisDate                int64                      `json:"whois_date,omitempty"`
	}
)

func (obj *IPAddressV3) GetID() string {
	return obj.ID
}
