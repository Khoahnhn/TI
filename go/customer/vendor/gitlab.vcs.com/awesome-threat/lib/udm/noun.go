package udm

type (
	Noun struct {
		GeneralNoun
		SecurityResult *SecurityResult `json:"security_result,omitempty"`
		VerdictInfo    *VerdictInfo    `json:"verdict_info,omitempty"`
		Relationship   *Relationship   `json:"relationship,omitempty"`
		Whois          *Whois          `json:"whois,omitempty"`
		Artifact       *Artifact       `json:"artifact,omitempty"`
		PopularityRank *PopularityRank `json:"popularity_rank,omitempty"`
		SSLCertificate *SSLCertificate `json:"ssl_certificate,omitempty"`
		Permission     *Permission     `json:"permission,omitempty"`
		DNSRecord      *DNSRecord      `json:"dns_record,omitempty"`
		HTTPRequest    *HTTPRequest    `json:"http_request,omitempty"`
	}

	GeneralNoun struct {
		Domain   *Domain   `json:"domain,omitempty"`
		IP       *IP       `json:"ip,omitempty"`
		URL      *URL      `json:"url,omitempty"`
		File     *File     `json:"file,omitempty"`
		Registry *Registry `json:"registry,omitempty"`
		User     *User     `json:"user,omitempty"`
		Email    *Email    `json:"email,omitempty"`
	}
)
