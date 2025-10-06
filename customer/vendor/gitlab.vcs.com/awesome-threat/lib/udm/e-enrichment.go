package udm

type (
	Enrichment struct {
		Whois               *ResponseEnrichmentWhois               `json:"whois,omitempty"`
		PopularityRank      *ResponseEnrichmentPopularityRank      `json:"popularity_ranks,omitempty"`
		PassiveDNSDomain    *ResponseEnrichmentPassiveDNSDomain    `json:"passive_dns_domain,omitempty"`
		PassiveDNSIPAddress *ResponseEnrichmentPassiveDNSIPAddress `json:"passive_dns_ipaddress,omitempty"`
		Subdomain           *ResponseEnrichmentSubdomain           `json:"subdomain,omitempty"`
		SiblingDomain       *ResponseEnrichmentSiblingDomain       `json:"sibling_domain,omitempty"`
		Artifact            *ResponseEnrichmentArtifact            `json:"artifact,omitempty"`
		LastDNSRecord       *ResponseEnrichmentDNSRecord           `json:"last_dns_record,omitempty"`
		Subnet              *ResponseEnrichmentSubnet              `json:"subnet,omitempty"`
		SSLCertificate      *ResponseEnrichmentSSLCertificate      `json:"ssl_certificate,omitempty"`
		HTTPRequest         *ResponseEnrichmentHTTPRequest         `json:"http_request,omitempty"`
	}

	ResponseEnrichmentWhois struct {
		Data  []*Whois `json:"data,omitempty"`
		Total int64    `json:"total"`
	}

	ResponseEnrichmentPassiveDNSDomain struct {
		Data  []*PassiveDNSDomain `json:"data,omitempty"`
		Total int64               `json:"total"`
	}

	ResponseEnrichmentPassiveDNSIPAddress struct {
		Data  []*PassiveDNSIPAddress `json:"data,omitempty"`
		Total int64                  `json:"total"`
	}

	ResponseEnrichmentSubdomain struct {
		Data  []*Subdomain `json:"data,omitempty"`
		Total int64        `json:"total"`
	}

	ResponseEnrichmentSiblingDomain struct {
		Data  []*SiblingDomain `json:"data,omitempty"`
		Total int64            `json:"total"`
	}

	ResponseEnrichmentPopularityRank struct {
		Data  []*PopularityRank `json:"data,omitempty"`
		Total int64             `json:"total"`
	}

	ResponseEnrichmentArtifact struct {
		Data  []*Artifact `json:"data,omitempty"`
		Total int64       `json:"total"`
	}

	ResponseEnrichmentDNSRecord struct {
		Data  []*DNSRecord `json:"data,omitempty"`
		Total int64        `json:"total"`
	}

	ResponseEnrichmentSubnet struct {
		Data  []*PassiveDNSIPAddress `json:"data,omitempty"`
		Total int64                  `json:"total"`
	}

	ResponseEnrichmentSSLCertificate struct {
		Data  []*SSLCertificate `json:"data,omitempty"`
		Total int64             `json:"total"`
	}

	ResponseEnrichmentHTTPRequest struct {
		Data  []*HTTPRequest `json:"data,omitempty"`
		Total int64          `json:"total"`
	}
)
